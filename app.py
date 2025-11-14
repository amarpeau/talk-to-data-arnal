import streamlit as st
import snowflake.connector
import requests
import json
import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Configuration
st.set_page_config(
    page_title="Talk to Data - Arnal",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS Custom pour un design moderne
st.markdown("""
    <style>
    /* Style général */
    .main {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    }
    
    /* En-tête personnalisé */
    .custom-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    /* Cards de résultats */
    .result-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 1rem 0;
    }
    
    /* Boutons stylisés */
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.5rem 2rem;
        font-weight: 600;
        transition: all 0.3s;
    }
    
    .stButton>button:hover {
        transform: scale(1.05);
        box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
    }
    
    /* Metrics personnalisées */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background-color: #f8f9fa;
        border-radius: 5px;
        font-weight: 600;
    }
    
    /* Dataframe */
    [data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    /* Tabs personnalisés */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: white;
        padding: 10px;
        border-radius: 10px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: 600;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    </style>
""", unsafe_allow_html=True)

# Configuration et connexion Snowflake
@st.cache_resource
def get_snowflake_connection():
    """Crée une connexion Snowflake avec authentification par clé privée"""
    
    import os
    
    # Essayer différents chemins pour la clé privée
    # 1. Chemin depuis secrets.toml (local)
    # 2. Chemin Render (/etc/secrets/)
    # 3. Chemin racine de l'app (/app/)
    
    possible_paths = [
        st.secrets["snowflake"].get("private_key_path", ""),
        "/etc/secrets/rsa_key.p8",  # Render Secret Files
        "/app/rsa_key.p8",           # Si copié dans l'app
        "rsa_key.p8"                 # Local
    ]
    
    private_key_pem = None
    
    for path in possible_paths:
        if path and os.path.exists(path):
            try:
                with open(path, "rb") as key_file:
                    private_key_pem = key_file.read()
                st.info(f"✅ Clé privée trouvée : {path}")
                break
            except Exception as e:
                st.warning(f"⚠️ Impossible de lire {path}: {e}")
                continue
    
    if private_key_pem is None:
        st.error("❌ Aucune clé privée trouvée dans les chemins suivants:")
        for path in possible_paths:
            st.error(f"  - {path} (existe: {os.path.exists(path) if path else 'N/A'})")
        raise FileNotFoundError("Private key not found")
    
    # Charger et convertir la clé privée en DER
    private_key_obj = serialization.load_pem_private_key(
        private_key_pem,
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

HOST = f"{st.secrets['snowflake']['account']}.snowflakecomputing.com"

def send_message_to_analyst(prompt: str):
    """Envoie une question à Cortex Analyst"""
    conn = get_snowflake_connection()
    
    api_messages = []
    if len(st.session_state.messages) > 0:
        last_assistant_idx = -1
        for i in range(len(st.session_state.messages) - 1, -1, -1):
            if st.session_state.messages[i]["role"] == "assistant":
                last_assistant_idx = i
                break
        
        if last_assistant_idx > 0:
            prev_user_msg = st.session_state.messages[last_assistant_idx - 1]
            api_messages.append({
                "role": "user",
                "content": [{"type": "text", "text": prev_user_msg["content"]}]
            })
            
            last_assistant_msg = st.session_state.messages[last_assistant_idx]
            if "response_data" in last_assistant_msg and "message" in last_assistant_msg["response_data"]:
                content_items = last_assistant_msg["response_data"]["message"].get("content", [])
                for item in content_items:
                    if item.get("type") == "text":
                        api_messages.append({
                            "role": "analyst",
                            "content": [{"type": "text", "text": item.get("text", "")}]
                        })
                        break
    
    api_messages.append({
        "role": "user",
        "content": [{"type": "text", "text": prompt}]
    })
    
    request_body = {
        "messages": api_messages,
        "semantic_view": "RESOTAINER.TALK_TO_DATA.TALK_2_DATA_REDUCED_DIM"
    }
    
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
            return {"error": f"Erreur API (request_id: {request_id}): {resp.text}"}
    except Exception as e:
        return {"error": str(e)}

def identify_meaningful_columns(df, question):
    """Identifie intelligemment les colonnes pertinentes pour la visualisation"""
    
    # Mots-clés à EXCLURE (identifiants, codes, clés)
    exclude_keywords = [
        'id', '_id', 'code', '_code', 'key', '_key', 
        'pk', 'fk', 'numero', 'num', 'reference', 'ref'
    ]
    
    # Mots-clés TEMPORELS
    time_keywords = ['date', 'mois', 'month', 'annee', 'year', 'jour', 'day', 'time', 'periode']
    
    # Mots-clés CATÉGORIELS (pour labels)
    label_keywords = ['nom', 'name', 'libelle', 'label', 'agence', 'depot', 'client', 'ville', 'city', 'ur_']
    
    # Mots-clés METRIQUES (pour valeurs)
    metric_keywords = [
        'montant', 'prix', 'price', 'valeur', 'value', 'total', 'somme', 'sum',
        'ca', 'chiffre', 'revenue', 'cout', 'cost', 'nombre', 'count', 'quantite', 'qty',
        'surface', 'taux', 'rate', 'ratio', 'pourcent', 'percent', '%',
        'volume', 'poids', 'weight', 'entrees', 'sorties', 'supplementaire', 'difference', 'suppl'
    ]
    
    def score_column(col_name, col_data):
        """Donne un score à une colonne selon sa pertinence"""
        col_lower = col_name.lower()
        score = {
            'name': col_name,
            'type': None,
            'score': 0,
            'reason': []
        }
        
        # EXCLUSION : ID et codes (score très négatif)
        if any(excl in col_lower for excl in exclude_keywords):
            score['score'] = -1000
            score['reason'].append('❌ Identifiant/code')
            score['type'] = 'exclude'
            return score
        
        # TYPE : Temporel
        if any(time in col_lower for time in time_keywords):
            score['score'] += 100
            score['reason'].append('📅 Temporel')
            score['type'] = 'temporal'
            return score
        
        # TYPE : Numérique métrique
        if pd.api.types.is_numeric_dtype(col_data):
            # C'est une colonne numérique
            
            # Vérifier si c'est une vraie métrique
            if any(metric in col_lower for metric in metric_keywords):
                score['score'] += 80
                score['reason'].append('📊 Métrique')
                score['type'] = 'metric'
            else:
                # Numérique mais sans mot-clé => score moyen
                score['score'] += 30
                score['reason'].append('🔢 Numérique')
                score['type'] = 'numeric'
            
            # Bonus si mentionné dans la question
            question_words = question.lower().split()
            col_words = col_lower.replace('_', ' ').split()
            if any(word in question_words for word in col_words if len(word) > 3):
                score['score'] += 50
                score['reason'].append('💡 Dans question')
            
            return score
        
        # TYPE : Catégoriel (label)
        if any(label in col_lower for label in label_keywords):
            score['score'] += 60
            score['reason'].append('🏷️  Label')
            score['type'] = 'label'
            return score
        
        # TYPE : Texte générique
        score['score'] += 20
        score['reason'].append('📝 Texte')
        score['type'] = 'text'
        
        return score
    
    # Scorer toutes les colonnes
    column_scores = []
    for col in df.columns:
        score_info = score_column(col, df[col])
        column_scores.append(score_info)
    
    # Trier par score
    column_scores.sort(key=lambda x: x['score'], reverse=True)
    
    # Trouver la meilleure colonne temporelle/label
    label_col = None
    for col_info in column_scores:
        if col_info['type'] in ['temporal', 'label', 'text'] and col_info['score'] > 0:
            label_col = col_info['name']
            break
    
    # Si pas de label trouvé, prendre la première colonne non-métrique
    if label_col is None:
        for col in df.columns:
            if not pd.api.types.is_numeric_dtype(df[col]):
                label_col = col
                break
    
    # Si toujours rien, prendre la première colonne
    if label_col is None:
        label_col = df.columns[0]
    
    # Trouver la meilleure colonne métrique (en excluant la colonne label)
    metric_col = None
    for col_info in column_scores:
        if col_info['type'] in ['metric', 'numeric'] and col_info['score'] > 0 and col_info['name'] != label_col:
            metric_col = col_info['name']
            break
    
    return {
        'label_col': label_col,
        'metric_col': metric_col,
        'all_scores': column_scores
    }

def analyze_data_characteristics(df, col_name):
    """Analyse les caractéristiques d'une colonne spécifique"""
    
    if col_name not in df.columns or not pd.api.types.is_numeric_dtype(df[col_name]):
        return {
            'is_visualizable': False,
            'reason': 'Colonne non numérique',
            'stats': {}
        }
    
    values = df[col_name]
    
    # Calculer les statistiques
    stats = {
        'count': len(values),
        'unique': values.nunique(),
        'mean': values.mean(),
        'std': values.std(),
        'min': values.min(),
        'max': values.max(),
        'range': values.max() - values.min()
    }
    
    # 1. Toutes les valeurs identiques
    if stats['unique'] <= 1:
        return {
            'is_visualizable': False,
            'reason': 'Toutes les valeurs sont identiques',
            'stats': stats
        }
    
    # 2. Coefficient de variation très faible
    if stats['mean'] != 0:
        cv = (stats['std'] / abs(stats['mean'])) * 100
        stats['cv'] = cv
        if cv < 1:
            return {
                'is_visualizable': False,
                'reason': f'Variation trop faible (CV: {cv:.2f}%)',
                'stats': stats
            }
    
    # 3. Amplitude relative trop faible
    if stats['max'] != 0:
        amplitude_ratio = (stats['range'] / abs(stats['max'])) * 100
        stats['amplitude_ratio'] = amplitude_ratio
        if amplitude_ratio < 5:
            return {
                'is_visualizable': False,
                'reason': f'Amplitude trop faible ({amplitude_ratio:.2f}%)',
                'stats': stats
            }
    
    return {
        'is_visualizable': True,
        'reason': 'Données visualisables',
        'stats': stats
    }

def detect_visualization_type(df, label_col):
    """Détecte le meilleur type de visualisation selon les données"""
    
    # Si on a des dates
    if pd.api.types.is_datetime64_any_dtype(df[label_col]) or 'date' in label_col.lower() or 'mois' in label_col.lower():
        return 'line'
    
    # Si on a peu de catégories (< 15)
    if len(df) <= 15:
        return 'bar'
    
    # Si on a beaucoup de catégories
    if len(df) > 15:
        return 'bar_horizontal'
    
    return 'bar'

def create_advanced_plotly_chart(df, question):
    """Crée un graphique Plotly interactif avancé avec sélection intelligente des colonnes"""
    if len(df.columns) < 2:
        return None, None
    
    # ÉTAPE 1 : Identifier les colonnes pertinentes
    col_analysis = identify_meaningful_columns(df, question)
    
    label_col = col_analysis['label_col']
    value_col = col_analysis['metric_col']
    
    # Debug : Afficher l'analyse dans un expander
    debug_info = f"""
**🔍 Analyse automatique des colonnes :**

**Colonne X (labels)** : `{label_col}`
**Colonne Y (valeurs)** : `{value_col or 'Aucune trouvée'}`

**Détail de l'analyse :**
"""
    for col_info in col_analysis['all_scores'][:5]:
        debug_info += f"\n• `{col_info['name']}` (score: {col_info['score']}): {', '.join(col_info['reason'])}"
    
    # Si pas de colonne métrique trouvée, impossible de créer un graphique
    if value_col is None:
        return None, {
            'type': 'warning',
            'message': f"⚠️ **Visualisation impossible**",
            'details': f"""
Aucune colonne métrique pertinente n'a été trouvée dans les données.

{debug_info}

💡 **Conseil** : Consultez le tableau de données pour voir toutes les informations.
            """
        }
    
    # ÉTAPE 2 : Analyser la variation de la colonne métrique
    analysis = analyze_data_characteristics(df, value_col)
    
    # Si les données ne sont pas visualisables, retourner None avec un message
    if not analysis['is_visualizable']:
        return None, {
            'type': 'warning',
            'message': f"⚠️ **Visualisation non pertinente** : {analysis['reason']}",
            'details': f"""
{debug_info}

**Statistiques de `{value_col}` :**
- Valeur min : {analysis['stats']['min']:,.2f}
- Valeur max : {analysis['stats']['max']:,.2f}
- Écart : {analysis['stats']['range']:,.2f}
- Écart-type : {analysis['stats']['std']:,.2f}

💡 **Conseil** : Consultez le tableau de données pour voir les valeurs exactes.
            """
        }
    
    viz_type = detect_visualization_type(df, label_col)
    
    # Créer le graphique selon le type
    if viz_type == 'line':
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df[label_col],
            y=df[value_col],
            mode='lines+markers',
            line=dict(color='rgba(102, 126, 234, 1)', width=3),
            marker=dict(size=8, color='rgba(102, 126, 234, 0.8)', 
                       line=dict(color='white', width=2)),
            fill='tozeroy',
            fillcolor='rgba(102, 126, 234, 0.2)',
            hovertemplate='<b>%{x}</b><br>%{y:,.0f}<extra></extra>'
        ))
    
    elif viz_type == 'bar_horizontal':
        # Trier par valeur décroissante
        df_sorted = df.sort_values(value_col, ascending=True)
        fig = go.Figure()
        fig.add_trace(go.Bar(
            y=df_sorted[label_col],
            x=df_sorted[value_col],
            orientation='h',
            marker=dict(
                color=df_sorted[value_col],
                colorscale='Blues',
                line=dict(color='rgba(102, 126, 234, 1)', width=1)
            ),
            hovertemplate='<b>%{y}</b><br>%{x:,.0f}<extra></extra>'
        ))
    
    else:  # bar
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=df[label_col],
            y=df[value_col],
            marker=dict(
                color=df[value_col],
                colorscale='Viridis',
                line=dict(color='rgba(102, 126, 234, 1)', width=1.5),
                cornerradius=8
            ),
            hovertemplate='<b>%{x}</b><br>%{y:,.0f}<extra></extra>'
        ))
    
    # Mise en forme
    fig.update_layout(
        title=dict(
            text=f"<b>{question}</b>",
            font=dict(size=20, color='#333'),
            x=0.5,
            xanchor='center'
        ),
        xaxis=dict(
            title=label_col,
            showgrid=False,
            showline=True,
            linewidth=2,
            linecolor='#e0e0e0'
        ),
        yaxis=dict(
            title=value_col,
            showgrid=True,
            gridwidth=1,
            gridcolor='rgba(0,0,0,0.05)'
        ),
        plot_bgcolor='white',
        paper_bgcolor='white',
        height=500,
        hovermode='closest',
        hoverlabel=dict(
            bgcolor="white",
            font_size=14,
            font_family="Arial"
        )
    )
    
    return fig, {'debug': debug_info}

def create_statistics_cards(df):
    """Crée des cartes de statistiques élégantes"""
    if len(df.columns) < 2:
        return
    
    # Trouver la première colonne numérique
    numeric_col = None
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            numeric_col = col
            break
    
    if numeric_col is None:
        st.info("ℹ️ Aucune colonne numérique trouvée pour les statistiques")
        return
    
    values = df[numeric_col]
    
    # Calculer les stats
    stats = {
        "Total": values.sum(),
        "Moyenne": values.mean(),
        "Maximum": values.max(),
        "Minimum": values.min()
    }
    
    # Afficher dans des colonnes
    cols = st.columns(4)
    icons = ["📊", "📈", "🔥", "❄️"]
    
    for idx, (label, value) in enumerate(stats.items()):
        with cols[idx]:
            if label == "Moyenne":
                st.metric(
                    label=f"{icons[idx]} {label}",
                    value=f"{value:.1f}"
                )
            else:
                st.metric(
                    label=f"{icons[idx]} {label}",
                    value=f"{value:,.0f}"
                )
    
    # Ajouter une ligne avec les statistiques avancées
    st.markdown("---")
    cols2 = st.columns(4)
    
    # Coefficient de variation
    cv = (values.std() / values.mean() * 100) if values.mean() != 0 else 0
    with cols2[0]:
        st.metric(
            label="📉 Écart-type",
            value=f"{values.std():.2f}"
        )
    
    with cols2[1]:
        st.metric(
            label="📊 Coef. Variation",
            value=f"{cv:.2f}%"
        )
    
    with cols2[2]:
        st.metric(
            label="📈 Médiane",
            value=f"{values.median():,.0f}"
        )
    
    with cols2[3]:
        amplitude = values.max() - values.min()
        st.metric(
            label="📏 Amplitude",
            value=f"{amplitude:,.0f}"
        )

def create_detailed_table(df):
    """Crée un tableau détaillé avec styling"""
    
    # Ajouter une colonne d'index pour l'affichage
    df_display = df.copy()
    df_display.insert(0, '#', range(1, len(df_display) + 1))
    
    # Styling du dataframe
    def highlight_max(s):
        if pd.api.types.is_numeric_dtype(s):
            is_max = s == s.max()
            return ['background-color: rgba(102, 126, 234, 0.2); font-weight: bold' if v else '' for v in is_max]
        return ['' for _ in s]
    
    styled_df = df_display.style.apply(highlight_max, subset=df.columns.tolist())
    
    st.dataframe(
        styled_df,
        use_container_width=True,
        height=400
    )

def display_response(response_data, user_question, unique_id=None):
    """Affiche la réponse de Cortex Analyst"""
    
    if "error" in response_data:
        st.error(f"❌ {response_data['error']}")
        return
    
    if "message" not in response_data or "content" not in response_data["message"]:
        st.error("Format de réponse invalide")
        return
    
    content = response_data["message"]["content"]
    sql_statement = None
    
    # Afficher le contenu
    for item in content:
        item_type = item.get("type", "")
        
        if item_type == "text":
            st.markdown(f"### 💡 {item.get('text', '')}")
        
        elif item_type == "sql":
            sql_statement = item.get("statement", "")
            with st.expander("🔍 Requête SQL", expanded=False):
                st.code(sql_statement, language="sql")
    
    # Exécuter le SQL et afficher les résultats
    if sql_statement:
        try:
            conn = get_snowflake_connection()
            cursor = conn.cursor()
            cursor.execute(sql_statement)
            
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            if rows:
                df = pd.DataFrame(rows, columns=columns)
                
                # Initialiser l'état si nécessaire
                if unique_id is None:
                    unique_id = response_data.get("request_id", str(hash(sql_statement)))
                
                show_key = f"show_advanced_{unique_id}"
                
                if show_key not in st.session_state:
                    st.session_state[show_key] = False
                
                # NIVEAU 1 : Aperçu rapide
                if not st.session_state[show_key]:
                    st.markdown("### 📊 Aperçu des résultats")
                    
                    # Afficher les premières lignes
                    st.dataframe(df.head(10), use_container_width=True)
                    
                    if len(df) > 10:
                        st.caption(f"Affichage de 10 lignes sur {len(df)} au total")
                    
                    # Bouton pour voir l'analyse complète
                    if len(df.columns) >= 2 and len(df) > 1:
                        st.markdown("---")
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown("### 🚀 Analyse Avancée Disponible")
                            st.write("Visualisation interactive, statistiques et données complètes")
                        
                        with col2:
                            if st.button("📈 Voir l'analyse", key=f"btn_show_{unique_id}", use_container_width=True):
                                st.session_state[show_key] = True
                                st.rerun()
                
                # NIVEAU 2 : Analyse complète
                else:
                    st.markdown("### 🎨 Analyse Avancée")
                    
                    # Onglets pour organiser l'information
                    tab1, tab2, tab3 = st.tabs(["📊 Visualisation", "📈 Statistiques", "📋 Données Complètes"])
                    
                    with tab1:
                        fig, info = create_advanced_plotly_chart(df, user_question)
                        
                        if info and info.get('type') == 'warning':
                            # Afficher le message d'avertissement avec style
                            st.warning(info['message'])
                            with st.expander("ℹ️ Plus de détails"):
                                st.markdown(info['details'])
                        elif fig:
                            st.plotly_chart(fig, use_container_width=True)
                            # Afficher le debug en expander
                            if info and 'debug' in info:
                                with st.expander("🔍 Détails de l'analyse automatique"):
                                    st.markdown(info['debug'])
                        else:
                            st.info("Visualisation non disponible pour ce type de données")
                    
                    with tab2:
                        st.markdown("#### 📊 Statistiques clés")
                        create_statistics_cards(df)
                        
                        # Informations additionnelles
                        st.markdown("---")
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.info(f"**Nombre de lignes:** {len(df)}")
                        with col2:
                            st.info(f"**Nombre de colonnes:** {len(df.columns)}")
                        with col3:
                            # Trouver une colonne numérique pour l'écart-type
                            numeric_cols = df.select_dtypes(include=['number']).columns
                            if len(numeric_cols) > 0:
                                col_name = numeric_cols[0]
                                st.info(f"**Écart-type:** {df[col_name].std():.2f}")
                            else:
                                st.info(f"**Type:** Données textuelles")
                    
                    with tab3:
                        st.markdown("#### 📋 Tableau complet")
                        create_detailed_table(df)
                        
                        # Option de téléchargement
                        csv = df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="📥 Télécharger en CSV",
                            data=csv,
                            file_name=f"analyse_{unique_id}.csv",
                            mime="text/csv",
                        )
                    
                    # Bouton pour fermer
                    if st.button("✖ Fermer l'analyse", key=f"btn_close_{unique_id}"):
                        st.session_state[show_key] = False
                        st.rerun()
            
            else:
                st.info("Aucun résultat trouvé.")
            
            cursor.close()
            
        except Exception as e:
            st.error(f"❌ Erreur : {str(e)}")

# En-tête personnalisé
st.markdown("""
    <div class="custom-header">
        <h1>🗣️ ARNAL RESOTAINER</h1>
        <p>Talk to Data - Posez vos questions en langage naturel</p>
    </div>
""", unsafe_allow_html=True)

# Initialisation
if "messages" not in st.session_state:
    st.session_state.messages = []

# Sidebar
with st.sidebar:
    st.markdown("### 🏢 ARNAL")
    st.markdown("---")
    
    st.markdown("### ℹ️ Informations")
    st.info("""
    **Semantic View**  
    TALK_2_DATA_REDUCED_DIM
    
    **Base de données**  
    RESOTAINER.TALK_TO_DATA
    """)
    
    if st.button("🗑️ Nouvelle conversation", use_container_width=True):
        st.session_state.messages = []
        # Nettoyer tous les états d'analyse avancée
        for key in list(st.session_state.keys()):
            if key.startswith("show_advanced_"):
                del st.session_state[key]
        st.rerun()
    
    st.markdown("---")
    st.caption("Powered by Snowflake Cortex Analyst")

# Affichage historique
for idx, message in enumerate(st.session_state.messages):
    with st.chat_message(message["role"]):
        if message["role"] == "user":
            st.markdown(message["content"])
        else:
            unique_id = message.get("response_data", {}).get("request_id", f"msg_{idx}")
            display_response(message["response_data"], message.get("user_question", ""), unique_id)

# Input
if prompt := st.chat_input("Quelle est votre question ?"):
    st.session_state.messages.append({
        "role": "user",
        "content": prompt
    })
    
    with st.chat_message("user"):
        st.markdown(prompt)
    
    with st.chat_message("assistant"):
        with st.spinner("⏳ Analyse en cours..."):
            response_data = send_message_to_analyst(prompt)
            unique_id = response_data.get("request_id", f"new_{len(st.session_state.messages)}")
            display_response(response_data, prompt, unique_id)
            
            st.session_state.messages.append({
                "role": "assistant",
                "content": "Response",
                "response_data": response_data,
                "user_question": prompt
            })

# Exemples au démarrage
if not st.session_state.messages:
    st.markdown("### 💡 Exemples de questions")
    
    examples = [
        ("📈", "Combien de réservations à Bordeaux en juin 2025 ?"),
        ("📊", "Quel est le taux de remplissage par agence ?"),
        ("🎯", "Quelles agences ont atteint leurs objectifs ?"),
    ]
    
    cols = st.columns(len(examples))
    for i, (icon, example) in enumerate(examples):
        if cols[i].button(f"{icon} {example}", use_container_width=True):
            st.session_state.example = example
            st.rerun()

if "example" in st.session_state:
    del st.session_state.example
