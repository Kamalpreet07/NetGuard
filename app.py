import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile
import os

from network_analysis import analyze_pcap
from speed_test import run_speed_test
from diagnostics import check_ping, check_dns, get_suggestions


st.set_page_config(
    page_title="NetGuard",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ NetGuard")
st.subheader("Smart Network Monitoring and Troubleshooting System")

st.write(
    "Monitor internet speed, analyze network packets "
    "and perform basic network health checks."
)


# Sidebar

st.sidebar.title("NetGuard Menu")

page = st.sidebar.radio(
    "Select a feature",
    [
        "Dashboard",
        "Internet Speed Test",
        "Network Packet Analysis",
        "Network Troubleshooting"
    ]
)


# Dashboard

if page == "Dashboard":

    st.header("Network Monitoring Dashboard")

    st.write(
        "Use the menu on the left to test your internet "
        "connection and analyze network traffic."
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Project", "NetGuard")
    col2.metric("Packet Analysis", "Available")
    col3.metric("Diagnostics", "Available")

    st.info(
        "Start with Internet Speed Test or "
        "Network Troubleshooting."
    )


# Internet Speed Test

elif page == "Internet Speed Test":

    st.header("Internet Speed Test")

    st.write(
        "Measure your current download speed, upload speed and ping."
    )

    if st.button("Start Speed Test"):

        try:
            with st.spinner("Testing internet speed..."):

                results = run_speed_test()

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Download Speed",
                str(results["download"]) + " Mbps"
            )

            col2.metric(
                "Upload Speed",
                str(results["upload"]) + " Mbps"
            )

            col3.metric(
                "Ping",
                str(results["ping"]) + " ms"
            )

            st.success("Speed test completed.")

        except Exception as error:

            st.error("Speed test failed: " + str(error))


# Network Packet Analysis

elif page == "Network Packet Analysis":

    st.header("Wireshark Network Packet Analysis")

    st.write(
        "Upload a PCAP or PCAPNG file captured using Wireshark."
    )

    uploaded_file = st.file_uploader(
        "Upload network capture file",
        type=["pcap", "pcapng"]
    )

    if uploaded_file is not None:

        if st.button("Analyze Packets"):

            temp_path = None

            try:
                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".pcap"
                ) as temp_file:

                    temp_file.write(uploaded_file.getvalue())
                    temp_path = temp_file.name

                with st.spinner("Analyzing packets..."):

                    result = analyze_pcap(temp_path)

                st.success("Packet analysis completed.")

                col1, col2 = st.columns(2)

                col1.metric(
                    "Total Packets",
                    result["total_packets"]
                )

                col2.metric(
                    "Total Data",
                    str(round(result["total_bytes"] / 1024, 2))
                    + " KB"
                )

                st.subheader("Protocol Distribution")

                if result["protocol_count"]:

                    protocol_df = pd.DataFrame(
                        list(result["protocol_count"].items()),
                        columns=["Protocol", "Packets"]
                    )

                    fig = px.pie(
                        protocol_df,
                        names="Protocol",
                        values="Packets",
                        title="Network Protocol Distribution"
                    )

                    st.plotly_chart(fig, use_container_width=True)

                    st.dataframe(
                        protocol_df,
                        use_container_width=True
                    )

                st.subheader("Source IP Addresses")

                source_df = pd.DataFrame(
                    list(result["source_count"].items()),
                    columns=["Source IP", "Packet Count"]
                )

                st.dataframe(
                    source_df,
                    use_container_width=True
                )

                st.subheader("Destination IP Addresses")

                destination_df = pd.DataFrame(
                    list(result["destination_count"].items()),
                    columns=["Destination IP", "Packet Count"]
                )

                st.dataframe(
                    destination_df,
                    use_container_width=True
                )

                st.subheader("Packet Details")

                packet_df = result["dataframe"]

                st.dataframe(
                    packet_df.head(500),
                    use_container_width=True
                )

                csv_data = packet_df.to_csv(index=False)

                st.download_button(
                    "Download Packet Analysis CSV",
                    data=csv_data,
                    file_name="netguard_packet_report.csv",
                    mime="text/csv"
                )

            except Exception as error:

                st.error(
                    "Packet analysis failed: " + str(error)
                )

            finally:

                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)


# Network Troubleshooting

elif page == "Network Troubleshooting":

    st.header("Network Troubleshooting")

    st.write(
        "Check basic internet connectivity and DNS resolution."
    )

    if st.button("Run Network Checks"):

        with st.spinner("Checking network..."):

            ping_result = check_ping()
            dns_result = check_dns()

        st.subheader("Ping Test")

        st.write("Status:", ping_result["status"])

        with st.expander("View ping details"):
            st.text(ping_result["details"])

        st.subheader("DNS Test")

        st.write("DNS Status:", dns_result["status"])

        if dns_result["status"] == "Working":

            st.write("Resolved IP:", dns_result["ip"])

            st.write(
                "DNS Response Time:",
                str(dns_result["response_time"]) + " ms"
            )

        else:

            st.write(dns_result.get("error", "DNS lookup failed."))

        suggestions = get_suggestions(
            ping_result["status"],
            dns_result["status"]
        )

        st.subheader("Troubleshooting Suggestions")

        for suggestion in suggestions:

            st.info(suggestion)
