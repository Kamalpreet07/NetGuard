
import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile
import os
from datetime import datetime

from modules.live_monitor import LiveNetworkMonitor
from modules.modules.security_monitor import SecurityMonitor
from modules.report_generator import generate_pdf_report

from network_analysis import analyze_pcap
from speed_test import run_speed_test
from diagnostics import run_diagnostics


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="NetGuard | Network Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# --------------------------------------------------
# CUSTOM DESIGN
# --------------------------------------------------

st.markdown("""
<style>

.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}

[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #263449;
}

h1, h2, h3 {
    color: #e2e8f0;
}

.metric-card {
    background: #172338;
    border: 1px solid #263b55;
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 10px;
}

.metric-label {
    color: #94a3b8;
    font-size: 14px;
}

.metric-value {
    color: #38bdf8;
    font-size: 27px;
    font-weight: bold;
}

.small-note {
    color: #94a3b8;
    font-size: 13px;
}

div.stButton > button {
    border-radius: 8px;
    border: 1px solid #2563eb;
    background-color: #1d4ed8;
    color: white;
    font-weight: bold;
}

div.stButton > button:hover {
    background-color: #2563eb;
    border-color: #38bdf8;
    color: white;
}

</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "security_monitor" not in st.session_state:
    st.session_state.security_monitor = SecurityMonitor()

if "live_monitor" not in st.session_state:
    st.session_state.live_monitor = LiveNetworkMonitor(
        packet_callback=st.session_state.security_monitor.analyze_packet
    )

if "speed_results" not in st.session_state:
    st.session_state.speed_results = None

if "diagnostics_results" not in st.session_state:
    st.session_state.diagnostics_results = None

if "pcap_results" not in st.session_state:
    st.session_state.pcap_results = None

if "last_analysis_name" not in st.session_state:
    st.session_state.last_analysis_name = None


live_monitor = st.session_state.live_monitor
security_monitor = st.session_state.security_monitor


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def format_bytes(value):

    value = float(value)

    if value >= 1024 ** 3:
        return f"{value / (1024 ** 3):.2f} GB"

    if value >= 1024 ** 2:
        return f"{value / (1024 ** 2):.2f} MB"

    if value >= 1024:
        return f"{value / 1024:.2f} KB"

    return f"{value:.2f} Bytes"


def metric_card(label, value):

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def show_no_data(message):

    st.info(message)


def get_live_stats():

    return live_monitor.get_statistics()


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.markdown("# 🛡️ NetGuard")
st.sidebar.caption("Smart Network Monitoring & Security")

st.sidebar.markdown("---")

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Dashboard",
        "Live Network Monitor",
        "Internet Speed Test",
        "Packet Analyzer",
        "Security Alerts",
        "Network Diagnostics",
        "Reports"
    ]
)

st.sidebar.markdown("---")

st.sidebar.markdown("### System Information")

stats = get_live_stats()

if stats["running"]:
    st.sidebar.success("Live monitoring active")
else:
    st.sidebar.warning("Live monitoring stopped")

st.sidebar.write(
    f"Packets captured: {stats['total_packets']}"
)

st.sidebar.write(
    f"Data captured: {format_bytes(stats['total_bytes'])}"
)

st.sidebar.markdown("---")
st.sidebar.caption("NetGuard 2.0 | Network Security Dashboard")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

if page == "Dashboard":

    st.title("🛡️ NetGuard Dashboard")

    st.write(
        "Monitor network activity, analyse traffic "
        "and identify possible security threats."
    )

    stats = get_live_stats()
    alerts = security_monitor.get_summary()

    st.markdown("### Network Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card(
            "Total Packets",
            stats["total_packets"]
        )

    with col2:
        metric_card(
            "Total Data",
            format_bytes(stats["total_bytes"])
        )

    with col3:
        metric_card(
            "Detected Protocols",
            len(stats["protocols"])
        )

    with col4:
        metric_card(
            "Security Alerts",
            alerts["total_alerts"]
        )

    st.markdown("### Security Overview")

    col1, col2, col3 = st.columns(3)

    with col1:
        metric_card("High Alerts", alerts["high"])

    with col2:
        metric_card("Medium Alerts", alerts["medium"])

    with col3:
        metric_card("Low Alerts", alerts["low"])

    st.markdown("### Network Traffic")

    if stats["traffic_history"]:

        traffic_df = pd.DataFrame(
            stats["traffic_history"]
        )

        fig = px.line(
            traffic_df,
            x="time",
            y="bytes",
            title="Recent Packet Traffic",
            labels={
                "time": "Time",
                "bytes": "Packet Size (Bytes)"
            }
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0b1120",
            plot_bgcolor="#172338"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:
        show_no_data(
            "No live traffic data yet. Start monitoring "
            "from the Live Network Monitor page."
        )

    st.markdown("### Protocol Distribution")

    if stats["protocols"]:

        protocol_df = pd.DataFrame(
            list(stats["protocols"].items()),
            columns=["Protocol", "Packets"]
        )

        fig = px.pie(
            protocol_df,
            names="Protocol",
            values="Packets",
            hole=0.45,
            title="Captured Protocols"
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0b1120"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:
        show_no_data("No protocol data available yet.")

    st.markdown("### Recent Security Alerts")

    recent_alerts = security_monitor.get_alerts()[:5]

    if recent_alerts:
        st.dataframe(
            pd.DataFrame(recent_alerts),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.success("No security alerts have been generated yet.")


# --------------------------------------------------
# LIVE NETWORK MONITOR
# --------------------------------------------------

elif page == "Live Network Monitor":

    st.title("📡 Live Network Monitor")

    st.write(
        "Capture and observe real network packets "
        "using TShark."
    )

    st.warning(
        "Live capture requires NetGuard to run locally "
        "on Kali Linux or another computer with TShark "
        "installed and capture permissions enabled. "
        "Streamlit Cloud cannot capture packets from "
        "your personal computer."
    )

    interfaces = live_monitor.get_interfaces()

    if interfaces:

        selected_interface = st.selectbox(
            "Select Network Interface",
            interfaces
        )

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button(
                "▶ Start Monitoring",
                use_container_width=True
            ):

                started = live_monitor.start_monitoring(
                    selected_interface
                )

                if started:
                    st.success("Monitoring started.")
                else:
                    st.error(
                        live_monitor.error or
                        "Monitoring could not be started."
                    )

        with col2:
            if st.button(
                "⏹ Stop Monitoring",
                use_container_width=True
            ):

                live_monitor.stop_monitoring()
                st.warning("Monitoring stopped.")

        with col3:
            if st.button(
                "🔄 Refresh Data",
                use_container_width=True
            ):
                st.rerun()

    else:

        st.error(
            "No network interfaces found. "
            "Check whether TShark is installed and available."
        )

        if live_monitor.error:
            st.code(live_monitor.error)

    stats = get_live_stats()

    if stats["running"]:
        st.success("Live packet capture is running.")
    else:
        st.info("Packet capture is currently stopped.")

    st.markdown("### Capture Statistics")

    col1, col2, col3 = st.columns(3)

    with col1:
        metric_card("Packets", stats["total_packets"])

    with col2:
        metric_card("Total Data", format_bytes(stats["total_bytes"]))

    with col3:
        metric_card("Protocols", len(stats["protocols"]))

    st.markdown("### Captured Protocols")

    if stats["protocols"]:

        protocol_df = pd.DataFrame(
            list(stats["protocols"].items()),
            columns=["Protocol", "Packets"]
        )

        st.bar_chart(
            protocol_df.set_index("Protocol")
        )

    else:
        show_no_data("No packets have been captured.")

    st.markdown("### Recent Packets")

    if stats["recent_packets"]:

        packet_df = pd.DataFrame(
            stats["recent_packets"]
        )

        st.dataframe(
            packet_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        show_no_data("No packet records available.")

    st.caption(
        "Use Refresh Data to update the displayed statistics."
    )

    if stats["error"]:
        st.error(stats["error"])


# --------------------------------------------------
# INTERNET SPEED TEST
# --------------------------------------------------

elif page == "Internet Speed Test":

    st.title("🌐 Internet Speed Test")

    st.write(
        "Measure download speed, upload speed and ping."
    )

    st.warning(
        "The result measures the internet connection "
        "of the machine running this Streamlit app. "
        "On Streamlit Cloud, it does not measure your "
        "personal laptop's connection."
    )

    if st.button("Run Speed Test", type="primary"):

        with st.spinner("Testing internet speed..."):

            st.session_state.speed_results = run_speed_test()

    result = st.session_state.speed_results

    if result:

        if result["success"]:

            st.success("Speed test completed.")

            col1, col2, col3 = st.columns(3)

            with col1:
                metric_card(
                    "Download",
                    f'{result["download"]} Mbps'
                )

            with col2:
                metric_card(
                    "Upload",
                    f'{result["upload"]} Mbps'
                )

            with col3:
                metric_card(
                    "Ping",
                    f'{result["ping"]} ms'
                )

            st.markdown("### Test Details")

            st.write("Server:", result["server"])
            st.write("Country:", result["location"])
            st.write("Provider:", result["sponsor"])
            st.write("Test Time:", result["timestamp"])

        else:

            st.error("Speed test could not be completed.")

            if result["error"]:
                st.code(result["error"])

    else:
        show_no_data("Run a speed test to see actual results.")


# --------------------------------------------------
# PACKET ANALYZER
# --------------------------------------------------

elif page == "Packet Analyzer":

    st.title("🔍 Network Packet Analyzer")

    st.write(
        "Upload a PCAP or PCAPNG file to analyse "
        "network packet information."
    )

    uploaded_file = st.file_uploader(
        "Upload Network Capture File",
        type=["pcap", "pcapng"]
    )

    if uploaded_file:

        st.write("Selected file:", uploaded_file.name)

        if st.button("Analyse Packets", type="primary"):

            temporary_path = None

            try:

                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".pcap"
                ) as temporary_file:

                    temporary_file.write(
                        uploaded_file.getvalue()
                    )

                    temporary_path = temporary_file.name

                with st.spinner("Analysing packets..."):

                    result = analyze_pcap(temporary_path)

                if result["success"]:

                    st.session_state.pcap_results = result
                    st.session_state.last_analysis_name = uploaded_file.name

                    st.success("Packet analysis completed.")

                else:

                    st.error("Packet analysis failed.")
                    st.code(result["error"] or "Unknown error")

            except Exception as error:
                st.error(str(error))

            finally:

                if temporary_path and os.path.exists(temporary_path):
                    os.remove(temporary_path)

    result = st.session_state.pcap_results

    if result:

        st.markdown("### Analysis Summary")

        col1, col2, col3 = st.columns(3)

        with col1:
            metric_card(
                "Total Packets",
                result["total_packets"]
            )

        with col2:
            metric_card(
                "Total Data",
                format_bytes(result["total_bytes"])
            )

        with col3:
            metric_card(
                "Protocols",
                len(result["protocol_count"])
            )

        st.markdown("### Protocol Distribution")

        if not result["top_protocols"].empty:

            fig = px.bar(
                result["top_protocols"],
                x="Protocol",
                y="Packets",
                title="Packets by Protocol"
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0b1120",
                plot_bgcolor="#172338"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        st.markdown("### Top Source IP Addresses")

        if not result["top_sources"].empty:
            st.dataframe(
                result["top_sources"],
                use_container_width=True,
                hide_index=True
            )
        else:
            show_no_data("No source IP information found.")

        st.markdown("### Top Destination IP Addresses")

        if not result["top_destinations"].empty:
            st.dataframe(
                result["top_destinations"],
                use_container_width=True,
                hide_index=True
            )
        else:
            show_no_data("No destination IP information found.")

        st.markdown("### Destination Ports")

        if not result["top_ports"].empty:
            st.dataframe(
                result["top_ports"],
                use_container_width=True,
                hide_index=True
            )
        else:
            show_no_data("No destination port information found.")

        st.markdown("### Packet Details")

        if not result["dataframe"].empty:

            st.dataframe(
                result["dataframe"],
                use_container_width=True,
                hide_index=True
            )

            csv_data = result["dataframe"].to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                "Download Packet Data CSV",
                data=csv_data,
                file_name="netguard_packet_analysis.csv",
                mime="text/csv"
            )


# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------

elif page == "Security Alerts":

    st.title("🚨 Security Monitoring & Alerts")

    st.write(
        "Review suspicious patterns detected in captured "
        "network packets."
    )

    summary = security_monitor.get_summary()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card("Total Alerts", summary["total_alerts"])

    with col2:
        metric_card("High", summary["high"])

    with col3:
        metric_card("Medium", summary["medium"])

    with col4:
        metric_card("Low", summary["low"])

    st.markdown("### Detection Rules")

    st.write(
        "- Possible Port Scan: one source contacts many "
        "different destination ports."
    )

    st.write(
        "- Repeated Network Activity: many packets from "
        "one source within one minute."
    )

    st.write(
        "- High Traffic Volume: a source transfers a "
        "large amount of data."
    )

    st.warning(
        "These are basic traffic-based indicators. "
        "An alert does not prove that an attack has occurred."
    )

    st.markdown("### Detected Alerts")

    alerts = security_monitor.get_alerts()

    if alerts:

        alert_df = pd.DataFrame(alerts)

        st.dataframe(
            alert_df,
            use_container_width=True,
            hide_index=True
        )

        csv_data = alert_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "Download Security Alerts CSV",
            data=csv_data,
            file_name="netguard_security_alerts.csv",
            mime="text/csv"
        )

    else:
        st.success("No security alerts detected yet.")

    if st.button("Clear Security Alerts"):

        security_monitor.clear_alerts()
        st.success("Security alerts cleared.")
        st.rerun()


# --------------------------------------------------
# NETWORK DIAGNOSTICS
# --------------------------------------------------

elif page == "Network Diagnostics":

    st.title("🧰 Network Troubleshooting")

    st.write(
        "Check internet connectivity, ping, packet loss "
        "and DNS resolution."
    )

    if st.button("Run Network Diagnostics", type="primary"):

        with st.spinner("Running network checks..."):

            st.session_state.diagnostics_results = (
                run_diagnostics()
            )

    result = st.session_state.diagnostics_results

    if result:

        internet = result["internet"]
        ping = result["ping"]
        dns = result["dns"]

        st.markdown("### Connectivity Status")

        col1, col2, col3 = st.columns(3)

        with col1:

            if internet["success"]:
                st.success("Internet Connected")
            else:
                st.error("Internet Check Failed")

        with col2:

            if ping["success"]:
                st.success("Ping Successful")
            else:
                st.warning("Ping Failed")

        with col3:

            if dns["success"]:
                st.success("DNS Working")
            else:
                st.error("DNS Failed")

        st.markdown("### Ping Results")

        col1, col2, col3 = st.columns(3)

        with col1:
            metric_card(
                "Average Latency",
                (
                    f'{ping["average_latency"]} ms'
                    if ping["average_latency"] is not None
                    else "Not measured"
                )
            )

        with col2:
            metric_card(
                "Packet Loss",
                (
                    f'{ping["packet_loss"]}%'
                    if ping["packet_loss"] is not None
                    else "Not measured"
                )
            )

        with col3:
            metric_card(
                "Packets Received",
                ping["packets_received"]
            )

        st.markdown("### DNS Results")

        if dns["success"]:

            st.write("Domain:", dns["domain"])
            st.write("Resolved IP:", dns["ip_address"])
            st.write(
                "Resolution Time:",
                f'{dns["response_time_ms"]} ms'
            )

        else:
            st.error(dns["error"] or "DNS resolution failed.")

        st.markdown("### Recommendations")

        for recommendation in result["recommendations"]:
            st.write("•", recommendation)

        st.caption(
            "Last checked: " + result["timestamp"]
        )

    else:
        show_no_data(
            "Run diagnostics to see actual network results."
        )


# --------------------------------------------------
# REPORT GENERATION
# --------------------------------------------------

elif page == "Reports":

    st.title("📄 NetGuard Reports")

    st.write(
        "Generate a PDF report containing available "
        "network statistics, security alerts, speed "
        "test results and diagnostics."
    )

    stats = get_live_stats()
    alerts = security_monitor.get_alerts()

    speed = st.session_state.speed_results
    diagnostics = st.session_state.diagnostics_results

    st.markdown("### Available Report Data")

    col1, col2, col3 = st.columns(3)

    with col1:
        metric_card(
            "Live Packets",
            stats["total_packets"]
        )

    with col2:
        metric_card(
            "Security Alerts",
            len(alerts)
        )

    with col3:
        metric_card(
            "PCAP Packets",
            (
                st.session_state.pcap_results["total_packets"]
                if st.session_state.pcap_results
                else "Not analysed"
            )
        )

    if st.button("Generate PDF Report", type="primary"):

        try:

            performance = (
                speed if speed else {
                    "status": "Not measured"
                }
            )

            report_buffer = generate_pdf_report(
                network_stats=stats,
                security_alerts=alerts,
                performance=performance,
                diagnostics=diagnostics
            )

            report_buffer.seek(0)

            st.download_button(
                "Download NetGuard PDF Report",
                data=report_buffer.getvalue(),
                file_name="NetGuard_Network_Report.pdf",
                mime="application/pdf"
            )

            st.success("PDF report generated successfully.")

        except Exception as error:

            st.error("Could not generate the PDF report.")
            st.code(str(error))

    st.caption(
        "Reports contain the data available during this "
        "application session. Unmeasured values are not "
        "replaced with sample results."
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.markdown("---")

st.markdown(
    """
    <div style="text-align:center;color:#64748b;">
        NetGuard 2.0 | Smart Network Monitoring & Security System
        <br>
        Built with Python and Streamlit
    </div>
    """,
    unsafe_allow_html=True
)
