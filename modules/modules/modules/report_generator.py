
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from datetime import datetime
from io import BytesIO


def generate_pdf_report(
    network_stats=None,
    security_alerts=None,
    performance=None,
    diagnostics=None
):
    network_stats = network_stats or {}
    security_alerts = security_alerts or []
    performance = performance or {}
    diagnostics = diagnostics or {}

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "NetGuardTitle",
        parent=styles["Title"],
        fontSize=23,
        textColor=colors.HexColor("#123B66"),
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "NetGuardSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#555555"),
        alignment=TA_CENTER,
        spaceAfter=18
    )

    heading_style = ParagraphStyle(
        "NetGuardHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#1769AA"),
        spaceBefore=14,
        spaceAfter=8
    )

    story = []

    story.append(Paragraph("NETGUARD 2.0", title_style))

    story.append(
        Paragraph(
            "Network Monitoring and Security Analysis Report",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            "Report generated: "
            + datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 15))

    # Network summary.
    story.append(
        Paragraph("1. Network Monitoring Summary", heading_style)
    )

    total_packets = network_stats.get("total_packets", "Not measured")
    total_bytes = network_stats.get("total_bytes", "Not measured")

    network_data = [
        ["Metric", "Measured Value"],
        ["Total Packets", str(total_packets)],
        ["Total Data (Bytes)", str(total_bytes)],
        [
            "Monitoring Status",
            str(network_stats.get("running", "Not measured"))
        ]
    ]

    network_table = Table(
        network_data,
        colWidths=[7 * cm, 9 * cm]
    )

    network_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1769AA")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F2F6FA"))
    ]))

    story.append(network_table)

    # Protocol summary.
    protocols = network_stats.get("protocols", {})

    story.append(
        Paragraph("2. Protocol Distribution", heading_style)
    )

    if protocols:
        protocol_data = [["Protocol", "Packet Count"]]

        for protocol, count in protocols.items():
            protocol_data.append([str(protocol), str(count)])

        protocol_table = Table(
            protocol_data,
            colWidths=[8 * cm, 8 * cm]
        )

        protocol_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1769AA")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7)
        ]))

        story.append(protocol_table)
    else:
        story.append(
            Paragraph(
                "No protocol measurements available.",
                styles["Normal"]
            )
        )

    # Performance summary.
    story.append(
        Paragraph("3. Internet Performance", heading_style)
    )

    performance_data = [["Metric", "Value"]]

    for key, value in performance.items():
        performance_data.append([str(key), str(value)])

    if len(performance_data) == 1:
        performance_data.append(["Status", "Not measured"])

    performance_table = Table(
        performance_data,
        colWidths=[8 * cm, 8 * cm]
    )

    performance_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1769AA")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(performance_table)

    # Diagnostics.
    story.append(
        Paragraph("4. Network Diagnostics", heading_style)
    )

    if diagnostics:
        diagnostic_data = [["Check", "Result"]]

        for key, value in diagnostics.items():
            diagnostic_data.append([str(key), str(value)])

        diagnostic_table = Table(
            diagnostic_data,
            colWidths=[8 * cm, 8 * cm]
        )

        diagnostic_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1769AA")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7)
        ]))

        story.append(diagnostic_table)
    else:
        story.append(
            Paragraph(
                "No diagnostic measurements available.",
                styles["Normal"]
            )
        )

    # Security alerts.
    story.append(
        Paragraph("5. Security Alerts", heading_style)
    )

    if security_alerts:
        alert_data = [
            ["Time", "Severity", "Alert Type", "Source"]
        ]

        for alert in security_alerts:
            alert_data.append([
                str(alert.get("time", "Unknown")),
                str(alert.get("severity", "Unknown")),
                str(alert.get("type", "Unknown")),
                str(alert.get("source", "Unknown"))
            ])

        alert_table = Table(
            alert_data,
            colWidths=[4 * cm, 2.5 * cm, 5 * cm, 4.5 * cm],
            repeatRows=1
        )

        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1769AA")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("FONTSIZE", (0, 0), (-1, -1), 8)
        ]))

        story.append(alert_table)
    else:
        story.append(
            Paragraph(
                "No security alerts recorded during this report.",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Note: This report contains measurements available "
            "at the time of generation. Security alerts are "
            "rule-based indicators and do not prove an attack.",
            styles["Italic"]
        )
    )

    document.build(story)

    buffer.seek(0)
    return buffer
