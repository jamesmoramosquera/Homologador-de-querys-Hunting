import re
import streamlit as st

st.set_page_config(
    page_title="Homologador Multi-EDR con Esquemas Oficiales",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .stTextArea textarea {
        font-family: 'Courier New', Courier, monospace;
        background-color: #1e1e1e;
        color: #d4d4d4;
    }
    .main-title {
        text-align: center;
        color: #00adb5;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='main-title'>🛡️ Homologador Multi-EDR (Motor Basado en Diccionarios Oficiales)</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Traducción precisa basada en los esquemas reales de Defender, CrowdStrike LogScale, Cortex XDR y Cytomic Orion</p>", unsafe_allow_html=True)

tab_traducir, tab_esquemas = st.tabs(["🔄 Homologador Inteligente", "📚 Referencia de Diccionarios"])

with tab_traducir:
    all_langs = {
        "kql": "KQL (Microsoft Defender / Sentinel)",
        "cql": "CQL (CrowdStrike LogScale)",
        "trend": "Trend Micro Vision One",
        "citomic": "Citomic SQL (Panda/WatchGuard)",
        "fql": "CrowdStrike Falcon FQL",
        "xql": "Palo Alto Cortex XDR (XQL)"
    }

    source_code = st.selectbox(
        "📥 Selecciona el Lenguaje de Origen de tu consulta:", 
        options=list(all_langs.keys()), 
        format_func=lambda x: all_langs[x]
    )

    query_in = st.text_area(
        "Pega tu consulta completa de Threat Hunting aquí:", 
        height=260, 
        placeholder="Ej: DeviceNetworkEvents | where Timestamp >= ago(30d) | where ActionType == 'ConnectionSuccess' | where RemoteUrl endswith '.azurewebsites.net'..."
    )

    ejecutar = st.button("🚀 Homologar con Esquemas Oficiales", type="primary")

    st.markdown("---")
    st.subheader("📋 Resultados de Traducción Oficial por Plataforma")

    target_langs = {k: v for k, v in all_langs.items() if k != source_code}

    def dictionary_translate(query: str, target_lang: str) -> str:
        if not query or not query.strip():
            return "// Pega una consulta válida en el cuadro superior..."

        q_clean = query.strip()
        q_lower = q_clean.lower()
        lines = q_clean.split("\n")

        is_network = "network" in q_lower or "remoteurl" in q_lower or "devicenetworkevents" in q_lower or "remoteip" in q_lower
        is_logon = "logon" in q_lower or "devicelogonevents" in q_lower
        is_file = "file" in q_lower or "filename" in q_lower or "folderpath" in q_lower or "devicefileevents" in q_lower
        is_registry = "registry" in q_lower or "deviceregistryevents" in q_lower

        # 1. Palo Alto Cortex XDR (XQL) - Basado en Diccionario xdr_data
        if target_lang == "xql":
            if is_network:
                res_lines = [
                    "config case_sensitive = false",
                    "| dataset = xdr_data",
                    "| filter event_type = ENUM.NETWORK"
                ]
            elif is_logon:
                res_lines = [
                    "config case_sensitive = true",
                    "| dataset = xdr_data",
                    "| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id in (4624, 4625)"
                ]
            elif is_file:
                res_lines = [
                    "config case_sensitive = false",
                    "| dataset = xdr_data",
                    "| filter event_type = ENUM.FILE"
                ]
            elif is_registry:
                res_lines = [
                    "config case_sensitive = false",
                    "| dataset = xdr_data",
                    "| filter event_type = ENUM.REGISTRY"
                ]
            else:
                res_lines = [
                    "config case_sensitive = false",
                    "| dataset = xdr_data",
                    "| filter event_type = ENUM.PROCESS"
                ]

            for line in lines:
                l = line.strip()
                if not l or l.startswith("//") or any(t in l.lower() for t in ["deviceprocessevents", "devicefileevents", "devicelogonevents", "devicenetworkevents", "deviceregistryevents"]):
                    continue
                l_trans = l
                l_trans = re.sub(r"(?i)\|\s*where\s+", "| filter ", l_trans)
                l_trans = re.sub(r"(?i)\|\s*summarize\s+", "| comp ", l_trans)
                l_trans = re.sub(r"(?i)\|\s*project\s+", "| fields ", l_trans)
                l_trans = re.sub(r"(?i)\|\s*order by\s+", "| sort desc ", l_trans)
                
                # Mapeo oficial de campos Defender -> Cortex XDR
                l_trans = re.sub(r"(?i)\bfilename\b", "action_process_image_name", l_trans)
                l_trans = re.sub(r"(?i)\bfolderpath\b", "action_process_image_path", l_trans)
                l_trans = re.sub(r"(?i)\bremoteurl\b", "dst_host_name", l_trans)
                l_trans = re.sub(r"(?i)\bremoteip\b", "dst_ip_address", l_trans)
                l_trans = re.sub(r"(?i)\blocalip\b", "src_ip_address", l_trans)
                l_trans = re.sub(r"(?i)\binitiatingprocessfilename\b", "actor_process_image_name", l_trans)
                l_trans = re.sub(r"(?i)\binitiatingprocessfolderpath\b", "actor_process_image_path", l_trans)
                l_trans = re.sub(r"(?i)\bprocesscommandline\b", "action_process_command_line", l_trans)
                l_trans = re.sub(r"(?i)\bdevicename\b", "agent_hostname", l_trans)
                l_trans = re.sub(r"(?i)\baccountname\b", "actor_primary_username", l_trans)
                l_trans = re.sub(r"(?i)\btimestamp\b", "_time", l_trans)
                
                l_trans = re.sub(r"in~\s*\(", "in (", l_trans)
                l_trans = re.sub(r"has_any\s*\(", "contains ", l_trans)
                l_trans = re.sub(r"has\s+", "contains ", l_trans)
                l_trans = re.sub(r"==\s*", "= ", l_trans)
                
                res_lines.append(l_trans)
            return "\n".join(res_lines)

        # 2. CrowdStrike LogScale (CQL) - Basado en event_simpleName
        elif target_lang == "cql":
            if is_network:
                res_lines = ['#event_simpleName=NetworkConnectIP4']
            elif is_logon:
                res_lines = ['#event_simpleName=UserLogon']
            elif is_file:
                res_lines = ['#event_simpleName=PeFileWritten']
            elif is_registry:
                res_lines = ['#event_simpleName=RegGenericValueUpdate']
            else:
                res_lines = ['#event_simpleName=ProcessRollup2']

            for line in lines:
                l = line.strip()
                if not l or l.startswith("//") or any(t in l.lower() for t in ["deviceprocessevents", "devicefileevents", "devicelogonevents", "devicenetworkevents", "deviceregistryevents"]):
                    continue
                l_trans = l
                l_trans = re.sub(r"(?i)\|\s*where\s+", "| ", l_trans)
                l_trans = re.sub(r"(?i)\|\s*project\s+", "| table([", l_trans)
                
                # Mapeo oficial de campos Defender -> LogScale (CQL)
                l_trans = re.sub(r"(?i)\bfilename\b", "FileName", l_trans)
                l_trans = re.sub(r"(?i)\bfolderpath\b", "ImageFileName", l_trans)
                l_trans = re.sub(r"(?i)\bremoteurl\b", "DomainName", l_trans)
                l_trans = re.sub(r"(?i)\bremoteip\b", "RemoteAddressIP4", l_trans)
                l_trans = re.sub(r"(?i)\blocalip\b", "LocalAddressIP4", l_trans)
                l_trans = re.sub(r"(?i)\binitiatingprocessfilename\b", "ParentBaseFileName", l_trans)
                l_trans = re.sub(r"(?i)\bprocesscommandline\b", "CommandLine", l_trans)
                l_trans = re.sub(r"(?i)\bdevicename\b", "ComputerName", l_trans)
                l_trans = re.sub(r"(?i)\baccountname\b", "UserName", l_trans)
                l_trans = re.sub(r"(?i)\btimestamp\b", "@timestamp", l_trans)
                
                res_lines.append(l_trans)
            return "\n".join(res_lines)

        # 3. Trend Micro Vision One
        elif target_lang == "trend":
            res_lines = []
            for line in lines:
                l = line.strip()
                if not l or l.startswith("//") or "|" in l and not "where" in l.lower():
                    continue
                l_trans = l.replace("| where", "").strip()
                l_trans = re.sub(r"(?i)\bfilename\b", "objectFileName", l_trans)
                l_trans = re.sub(r"(?i)\bfolderpath\b", "objectFilePath", l_trans)
                l_trans = re.sub(r"(?i)\bremoteurl\b", "remoteUrl", l_trans)
                l_trans = re.sub(r"(?i)\bprocesscommandline\b", "processCommandLine", l_trans)
                l_trans = re.sub(r"==\s*", ": ", l_trans)
                res_lines.append(l_trans)
            return " AND ".join(res_lines) if res_lines else 'objectFilePath: "*"'

        # 4. Citomic SQL (Panda/WatchGuard) - Basado en tablas ProcessOps, NetworkOps, RegistryOps, LoginOutOps
        elif target_lang == "citomic":
            if is_network:
                sql_lines = [
                    "SELECT DateTime, MUID, ParentFilename, RemoteIp, RemotePort, Hostname, count() AS Connections",
                    "FROM NetworkOps",
                    "WHERE DateTime >= DATEADD(day, -30, GETDATE())"
                ]
            elif is_logon:
                sql_lines = [
                    "SELECT DateTime, MUID, Username, RemoteIp, SessionType",
                    "FROM LoginOutOps",
                    "WHERE DateTime >= DATEADD(day, -30, GETDATE())"
                ]
            elif is_file:
                sql_lines = [
                    "SELECT DateTime, MUID, LoggedUser, ParentFilename, ChildFilename, ChildPath",
                    "FROM DataAccess",
                    "WHERE DateTime >= DATEADD(day, -30, GETDATE())"
                ]
            elif is_registry:
                sql_lines = [
                    "SELECT DateTime, MUID, LoggedUser, ParentFilename, RegistryAction, Key, Value",
                    "FROM RegistryOps",
                    "WHERE DateTime >= DATEADD(day, -30, GETDATE())"
                ]
            else:
                sql_lines = [
                    "SELECT DateTime, MUID, LoggedUser, ParentFilename, ChildFilename, CommandLine",
                    "FROM ProcessOps",
                    "WHERE Operation = 0 AND DateTime >= DATEADD(day, -30, GETDATE())"
                ]

            for line in lines:
                l = line.strip()
                if not l or l.startswith("//") or "|" in l and not "where" in l.lower():
                    continue
                l_trans = l.replace("| where", "").replace("where", "").strip()
                l_trans = re.sub(r"(?i)\bfilename\b", "ChildFilename", l_trans)
                l_trans = re.sub(r"(?i)\bfolderpath\b", "ChildPath", l_trans)
                l_trans = re.sub(r"(?i)\bremoteurl\b", "Hostname", l_trans)
                l_trans = re.sub(r"(?i)\bremoteip\b", "RemoteIp", l_trans)
                l_trans = re.sub(r"(?i)\bprocesscommandline\b", "CommandLine", l_trans)
                l_trans = re.sub(r"(?i)\baccountname\b", "LoggedUser", l_trans)
                l_trans = re.sub(r"(?i)\bdevicename\b", "MUID", l_trans)
                l_trans = re.sub(r"endswith\s+['\"]([^'\"]+)['\"]", r"LIKE '%\1'", l_trans, flags=re.IGNORECASE)
                l_trans = re.sub(r"in~\s*\((.*?)\)", r"IN (\1)", l_trans)
                l_trans = re.sub(r"==\s*", "= ", l_trans)
                if l_trans:
                    sql_lines.append(f"  AND {l_trans}")
            
            if is_network:
                sql_lines.append("GROUP BY DateTime, MUID, ParentFilename, RemoteIp, RemotePort, Hostname\nORDER BY Connections DESC;")
            else:
                sql_lines.append("ORDER BY DateTime DESC;")
            return "\n".join(sql_lines)

        # 5. Falcon FQL
        elif target_lang == "fql":
            matches = re.findall(r"['\"]([a-zA-Z0-9_\-\.\*]+)['\"]", query)
            filters = []
            for m in matches:
                if len(m) > 2 and m.lower() not in ["deviceprocessevents", "devicefileevents", "devicenetworkevents", "deviceregistryevents", "filecreated", "actiontype", "filename", "folderpath", "timestamp", "remoteurl"]:
                    if "." in m:
                        filters.append(f"file_name:'*{m}*'")
                    else:
                        filters.append(f"indicator:'*{m}*'")
            if not filters:
                filters = ["platform_name:'Windows'", "status:'normal'"]
            return "+".join(filters[:4])

        # 6. KQL (Defender XDR)
        elif target_lang == "kql":
            return q_clean

        return q_clean

    if ejecutar:
        if not query_in.strip():
            st.warning("⚠️ Por favor, ingresa una consulta válida en el cuadro superior.")
        else:
            for t_code, t_name in target_langs.items():
                st.markdown(f"### 🎯 Destino: **{t_name}**")
                resultado = dictionary_translate(query_in, t_code)
                st.text_area(f"Salida {t_code}", value=resultado, height=240, key=f"smart_out_{t_code}")
                st.markdown("---")
    else:
        st.info("💡 Ingresa tu consulta arriba y haz clic en el botón para homologar utilizando los esquemas de tus diccionarios oficiales.")

with tab_esquemas:
    st.subheader("📚 Resumen de Diccionarios Oficiales Integrados")
    st.markdown("""
    * **Microsoft Defender XDR (KQL):** Tablas estándar como `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`.
    * **Cortex XDR (XQL):** Dataset único `xdr_data` con filtrado por `event_type` (`ENUM.PROCESS`, `ENUM.NETWORK`, `ENUM.FILE`, `ENUM.REGISTRY`) y jerarquía de actores (`actor_process_image_name`, `action_process_image_name`).
    * **CrowdStrike LogScale (CQL):** Eventos indexados por `#event_simpleName` (`ProcessRollup2`, `NetworkConnectIP4`, `PeFileWritten`, `RegGenericValueUpdate`).
    * **Cytomic Orion (SQL):** Tablas relacionales con esquema nativo de Panda/WatchGuard (`ProcessOps`, `NetworkOps`, `RegistryOps`, `LoginOutOps`, `DataAccess`) usando `MUID`, `ParentFilename` y `ChildFilename`.
    """)

st.markdown("---")
st.info("💡 **Estado:** Aplicación actualizada con mapeo exacto basado en diccionarios oficiales.")