import streamlit as st
import snowflake.connector
import requests
import json
import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Configuration de la page
st.set_page_config(
    page_title="Talk to Data - Arnal",
    page_icon="📊",
    layout="wide"
)

# Configuration et connexion Snowflake
@st.cache_resource
def get_snowflake_connection():
    """Crée une connexion Snowflake avec authentification par clé privée"""
    
    # Charger et convertir la clé privée en DER
    with open(st.secrets["snowflake"]["private_key_path"], "rb") as key_file:
        private_key_obj = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        private_key_der = private_key_obj.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    conn = snowflake.connector.connect(
        user=st.secrets["snowflake"]["user"],
        account=st.secrets["snowflake"]["account"],
        private_key=private_key_der,
        role=st.secrets["snowflake"]["role"],
        warehouse=st.secrets["snowflake"]["warehouse"],
        database=st.secrets["snowflake"]["database"],
        schema=st.secrets["snowflake"]["schema"]
    )
    
    return conn

# Host Snowflake
HOST = f"{st.secrets['snowflake']['account']}.snowflakecomputing.com"

def send_message_to_analyst(prompt: str):
    """
    Envoie une question à Cortex Analyst
    IMPORTANT: Ne construit les messages QUE depuis le dernier message assistant
    pour éviter l'erreur "Role must change after every message"
    """
    conn = get_snowflake_connection()
    
    # Construire les messages pour l'API
    # CRITIQUE: On ne garde QUE la dernière paire user/analyst de l'historique
    api_messages = []
    
    if len(st.session_state.messages) > 0:
        # Chercher le dernier message assistant
        last_assistant_idx = -1
        for i in range(len(st.session_state.messages) - 1, -1, -1):
            if st.session_state.messages[i]["role"] == "assistant":
                last_assistant_idx = i
                break
        
        # Si on a trouvé un message assistant, inclure la paire user/analyst précédente
        if last_assistant_idx > 0:
            # Le message user juste avant le dernier assistant
            prev_user_msg = st.session_state.messages[last_assistant_idx - 1]
            api_messages.append({
                "role": "user",
                "content": [{"type": "text", "text": prev_user_msg["content"]}]
            })
            
            # Le dernier message assistant
            last_assistant_msg = st.session_state.messages[last_assistant_idx]
            if "response_data" in last_assistant_msg and "message" in last_assistant_msg["response_data"]:
                # Extraire le texte de la dernière réponse
                content_items = last_assistant_msg["response_data"]["message"].get("content", [])
                for item in content_items:
                    if item.get("type") == "text":
                        api_messages.append({
                            "role": "analyst",
                            "content": [{"type": "text", "text": item.get("text", "")}]
                        })
                        break
    
    # Ajouter la nouvelle question
    api_messages.append({
        "role": "user",
        "content": [{"type": "text", "text": prompt}]
    })
    
    # Corps de la requête
    request_body = {
        "messages": api_messages,
        "semantic_view": "RESOTAINER.TALK_TO_DATA.TALK_2_DATA_REDUCED_DIM"
    }
    
    # Appel API REST
    try:
        resp = requests.post(
            url=f"https://{HOST}/api/v2/cortex/analyst/message",
            json=request_body,
            headers={
                "Authorization": f'Snowflake Token="{conn.rest.token}"',
                "Content-Type": "application/json",
            },
            timeout=60
        )
        
        request_id = resp.headers.get("X-Snowflake-Request-Id")
        
        if resp.status_code < 400:
            return {**resp.json(), "request_id": request_id}
        else:
            return {
                "error": f"Erreur API (request_id: {request_id}): {resp.text}"
            }
    except Exception as e:
        return {"error": str(e)}

def display_response(response_data):
    """Affiche la réponse de Cortex Analyst"""
    
    if "error" in response_data:
        st.error(f"❌ {response_data['error']}")
        return
    
    if "message" not in response_data or "content" not in response_data["message"]:
        st.error("Format de réponse invalide")
        if st.session_state.get("debug_mode", False):
            st.json(response_data)
        return
    
    content = response_data["message"]["content"]
    sql_statement = None
    
    # Parcourir et afficher chaque élément de content
    for item in content:
        item_type = item.get("type", "")
        
        if item_type == "text":
            st.markdown(item.get("text", ""))
        
        elif item_type == "sql":
            sql_statement = item.get("statement", "")
            with st.expander("🔍 Requête SQL générée", expanded=False):
                st.code(sql_statement, language="sql")
        
        elif item_type == "suggestions":
            with st.expander("💡 Suggestions"):
                for suggestion in item.get("suggestions", []):
                    st.info(suggestion)
    
    # NOUVEAU : Exécuter le SQL et afficher les résultats
    if sql_statement:
        try:
            conn = get_snowflake_connection()
            cursor = conn.cursor()
            cursor.execute(sql_statement)
            
            # Récupérer les résultats
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            if rows:
                # Créer un DataFrame pandas
                import pandas as pd
                df = pd.DataFrame(rows, columns=columns)
                
                st.subheader("📊 Résultats")
                
                # Afficher le tableau
                st.dataframe(df, use_container_width=True)
                
                # Proposer un graphique si approprié
                if len(df.columns) == 2 and len(df) > 1:
                    chart_type = st.radio("Type de graphique", ["Tableau seul", "Graphique en barres", "Graphique linéaire"], horizontal=True)
                    
                    if chart_type == "Graphique en barres":
                        st.bar_chart(df.set_index(df.columns[0]))
                    elif chart_type == "Graphique linéaire":
                        st.line_chart(df.set_index(df.columns[0]))
            else:
                st.info("La requête n'a retourné aucun résultat.")
            
            cursor.close()
            
        except Exception as e:
            st.error(f"❌ Erreur lors de l'exécution du SQL : {str(e)}")
            if st.session_state.get("debug_mode", False):
                st.exception(e)

# Interface
st.title("🗣️ Talk to Data - Arnal")
st.caption("Posez des questions sur vos données RESOTAINER")

# Initialisation
if "messages" not in st.session_state:
    st.session_state.messages = []

# Sidebar
with st.sidebar:
    st.header("ℹ️ Info")
    st.info("""
    **Semantic View**: TALK_2_DATA_REDUCED_DIM
    
    Base: RESOTAINER.TALK_TO_DATA
    """)
    
    st.session_state.debug_mode = st.checkbox("🔧 Debug", value=False)
    
    if st.button("🗑️ Effacer"):
        st.session_state.messages = []
        st.rerun()

# Affichage historique
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        if message["role"] == "user":
            st.markdown(message["content"])
        else:
            display_response(message["response_data"])

# Input
if prompt := st.chat_input("Votre question..."):
    # Ajouter message user
    st.session_state.messages.append({
        "role": "user",
        "content": prompt
    })
    
    with st.chat_message("user"):
        st.markdown(prompt)
    
    # Obtenir réponse
    with st.chat_message("assistant"):
        with st.spinner("⏳"):
            response_data = send_message_to_analyst(prompt)
            display_response(response_data)
            
            st.session_state.messages.append({
                "role": "assistant",
                "content": "Response",
                "response_data": response_data
            })

# Exemples
if not st.session_state.messages:
    st.subheader("💡 Exemples")
    
    examples = [
        "Combien de sites actifs ?",
        "Activité en mai 2025",
        "Sites à Bordeaux"
    ]
    
    cols = st.columns(len(examples))
    for i, example in enumerate(examples):
        if cols[i].button(example):
            st.session_state.example = example
            st.rerun()

if "example" in st.session_state:
    del st.session_state.example