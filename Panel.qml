import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "Model.js" as Model

// Local Wazuh agent status, entirely inside the Quickshell bar: no separate
// GUI window, no manager or API connection. All data collection happens in
// bin/omarchy-wazuh-state (config, SCA, FIM, rootcheck, logs, connection
// state, all read-only from files and databases the agent already writes).
// This file only renders whatever that script reports; the install path is
// detected at runtime, never assumed.
Panel {
  id: root
  moduleName: "devinblack001.wazuh-view"
  ipcTarget: "devinblack001.wazuh-view"
  manageIpc: false

  readonly property string script: String(Qt.resolvedUrl("bin/omarchy-wazuh-state")).replace(/^file:\/\//, "")

  property var payload: null
  property bool loadFailed: false
  property int activeTab: 0

  readonly property bool installed: !!(payload && payload.installed === true)
  readonly property var connectionData: payload ? payload.connection : null
  readonly property var configData: payload ? payload.config : null
  readonly property var scaData: payload ? payload.sca : null
  readonly property var fimData: payload ? payload.fim : null
  readonly property var rootcheckData: payload ? payload.rootcheck : null
  readonly property var logsData: payload ? payload.logs : null
  readonly property var moduleStatusData: payload ? payload.moduleStatus : null

  readonly property var modules: (configData && configData.modules) ? configData.modules : ({})
  readonly property var connectionFields: (connectionData && connectionData.fields) ? connectionData.fields : ({})
  readonly property var scaTotals: scaData ? scaData.totals : null
  readonly property var scaScans: (scaData && scaData.scans) ? scaData.scans : []
  readonly property var scaFailed: (scaData && scaData.failedChecks) ? scaData.failedChecks : []
  readonly property var fimSample: (fimData && fimData.sample) ? fimData.sample : []
  readonly property var logEntries: (logsData && logsData.recent) ? logsData.recent : []
  readonly property var fimDirs: (configData && configData.fimDirs) ? configData.fimDirs : []
  readonly property var logFiles: (configData && configData.logFiles) ? configData.logFiles : []
  readonly property var scaPolicyNames: (configData && configData.scaPolicies) ? configData.scaPolicies : []
  readonly property var activeResponses: (configData && configData.activeResponses) ? configData.activeResponses : []

  readonly property var summary: Model.summarize(payload)
  readonly property string overallStatus: summary.status

  // Cached IPC serialization, rebuilt once per refresh (see onStreamFinished)
  // instead of on every external state() call.
  property string cachedStateJson: JSON.stringify({ status: "", payload: null })

  function statusColor(status) {
    if (status === "bad") return root.bar.urgent
    if (status === "warn") return Color.accent
    if (status === "unknown") return Qt.darker(root.bar.foreground, 1.6)
    return root.bar.foreground
  }

  function refresh() {
    if (!stateProc.running) stateProc.running = true
  }

  function stateIpc() {
    return root.cachedStateJson
  }

  // JS string length counts UTF-16 code units, not UTF-8 bytes. maxPayloadBytes
  // is a byte budget, so measure it properly rather than relying on .length.
  function utf8ByteLength(str) {
    var bytes = 0
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i)
      if (code >= 0xD800 && code <= 0xDBFF && i + 1 < str.length) {
        var next = str.charCodeAt(i + 1)
        if (next >= 0xDC00 && next <= 0xDFFF) {
          bytes += 4
          i++
          continue
        }
      }
      if (code <= 0x7F) bytes += 1
      else if (code <= 0x7FF) bytes += 2
      else bytes += 3
    }
    return bytes
  }

  IpcHandler {
    target: "devinblack001.wazuh-view"
    function state(): string { return root.stateIpc() }
    function open() { root.open() }
    function close() { root.close() }
    function toggle() { root.toggle() }
    function show() { root.open() }
    function hide() { root.close() }
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Component.onCompleted: refresh()
  onOpenedChanged: if (opened) refresh()

  // Slow poll always (bar icon reflects live status), faster poll while the
  // panel is open. Local file/db reads are cheap, no need to go as fast as
  // a live tail.
  Timer {
    interval: root.opened ? 5000 : 30000
    running: true
    repeat: true
    onTriggered: root.refresh()
  }

  // Belt-and-suspenders cap on top of the helper's own output limits: the
  // helper's JSON payload should never approach this, so hitting it means
  // something is behaving unexpectedly and we should discard it rather
  // than hand a huge string to JSON.parse.
  readonly property int maxPayloadBytes: 2 * 1024 * 1024

  Process {
    id: stateProc
    command: [root.script]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var raw = String(text || "null")
        if (root.utf8ByteLength(raw) > root.maxPayloadBytes) {
          root.loadFailed = true
          return
        }
        try {
          root.payload = JSON.parse(raw)
          root.loadFailed = root.payload === null
        } catch (e) {
          root.loadFailed = true
        }
        root.cachedStateJson = JSON.stringify({ status: root.overallStatus, payload: root.payload })
      }
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""  // nf-fa-shield
    active: root.overallStatus === "bad" || root.overallStatus === "warn"
    onPressed: function(b) { root.toggle() }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: scrollArea
        anchors.fill: parent
        contentWidth: width
        contentHeight: panelColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        Column {
          id: panelColumn
          width: scrollArea.width
          spacing: Style.space(14)

          // ---------- Hero ----------
          Item {
            width: parent.width
            implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

            Text {
              id: heroIcon
              text: ""  // nf-fa-shield
              color: root.statusColor(root.overallStatus)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.display
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
            }

            Column {
              id: heroLabels
              anchors.left: heroIcon.right
              anchors.leftMargin: Style.space(14)
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(2)

              Text {
                text: "Wazuh View"
                color: root.bar.foreground
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
                width: parent.width
              }

              Text {
                text: root.summary.label
                color: root.statusColor(root.overallStatus)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.2
                elide: Text.ElideRight
                width: parent.width
              }
            }
          }

          // ---------- Not installed / loading ----------
          PanelSeparator { foreground: root.bar.foreground; visible: !root.installed }

          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: !root.installed

            Text {
              text: root.payload ? "No Wazuh agent detected on this machine." : (root.loadFailed ? "Failed to read agent state." : "Checking for a local Wazuh agent...")
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Text {
              visible: !!root.payload && !root.installed
              text: "Set WAZUH_HOME if the agent lives outside /var/ossec or /opt/ossec."
              color: Qt.darker(root.bar.foreground, 1.6)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }
          }

          // ---------- Tab bar ----------
          PanelSeparator { foreground: root.bar.foreground; visible: root.installed }

          Row {
            width: parent.width
            spacing: Style.space(6)
            visible: root.installed

            Repeater {
              model: [
                { label: "Overview", index: 0 },
                { label: "SCA", index: 1 },
                { label: "FIM", index: 2 },
                { label: "Rootcheck", index: 3 },
                { label: "Config", index: 4 },
                { label: "Logs", index: 5 }
              ]

              TabButtonItem {
                required property var modelData
                label: modelData.label
                index: modelData.index
              }
            }
          }

          PanelSeparator { foreground: root.bar.foreground; visible: root.installed }

          // ---------- Overview ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.installed && root.activeTab === 0

            PanelSectionHeader { text: "CONNECTION"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
            KeyValueRow { k: "Status"; v: Model.fieldOrDash(root.connectionFields.status); vColor: root.statusColor(Model.connectionStatus(root.connectionData)) }
            KeyValueRow { k: "Last keepalive"; v: Model.fieldOrDash(root.connectionFields.last_keepalive) }
            KeyValueRow { k: "Messages sent"; v: Model.fieldOrDash(root.connectionFields.msg_count) }
            KeyValueRow { k: "Manager"; v: Model.fieldOrDash(root.configData ? root.configData.manager : null) }
            KeyValueRow { k: "Agent version"; v: Model.fieldOrDash(root.payload ? root.payload.version : null) }
            KeyValueRow { k: "Install path"; v: Model.fieldOrDash(root.payload ? root.payload.agentHome : null) }

            PanelSeparator { foreground: root.bar.foreground }
            PanelSectionHeader { text: "MODULES"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
            KeyValueRow { k: "File integrity (FIM)"; v: Model.boolLabel(root.modules.fim); vColor: root.statusColor(Model.moduleStatus(root.modules.fim)) }
            KeyValueRow { k: "Rootcheck"; v: Model.boolLabel(root.modules.rootcheck); vColor: root.statusColor(Model.moduleStatus(root.modules.rootcheck)) }
            KeyValueRow { k: "SCA"; v: Model.boolLabel(root.modules.sca); vColor: root.statusColor(Model.moduleStatus(root.modules.sca)) }
            KeyValueRow { k: "Active response"; v: Model.boolLabel(root.modules.activeResponse); vColor: root.statusColor(Model.moduleStatus(root.modules.activeResponse)) }

            Column {
              width: parent.width
              spacing: Style.space(3)
              visible: !!root.moduleStatusData

              Text {
                text: "PROCESSES"
                color: Qt.darker(root.bar.foreground, 1.6)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                font.letterSpacing: 1.0
              }

              Repeater {
                model: root.moduleStatusData ? Object.keys(root.moduleStatusData) : []

                KeyValueRow {
                  required property var modelData
                  k: modelData
                  v: root.moduleStatusData[modelData] ? "running" : "not running"
                  vColor: root.moduleStatusData[modelData] ? root.bar.foreground : root.bar.urgent
                }
              }
            }
          }

          // ---------- SCA ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.installed && root.activeTab === 1

            Text {
              visible: !root.scaData || !root.scaData.readable
              text: root.scaData ? Model.errorLabel(root.scaData.error) : "Loading..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Column {
              width: parent.width
              spacing: Style.space(8)
              visible: !!(root.scaData && root.scaData.readable)

              PanelSectionHeader { text: "RESULTS"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
              KeyValueRow { k: "Totals"; v: Model.totalsSummary(root.scaTotals) }

              Repeater {
                model: root.scaScans

                Column {
                  id: scanCard
                  required property var modelData
                  width: parent.width
                  spacing: Style.space(2)

                  KeyValueRow { k: Model.fieldOrDash(scanCard.modelData.name); v: Model.scanSummary(scanCard.modelData) }
                  KeyValueRow {
                    k: "Score"
                    v: (scanCard.modelData.score !== null && scanCard.modelData.score !== undefined) ? (scanCard.modelData.score + "%") : "-"
                  }
                }
              }

              PanelSeparator { foreground: root.bar.foreground; visible: root.scaFailed.length > 0 }
              PanelSectionHeader { text: "FAILED CHECKS"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: root.scaFailed.length > 0 }

              Repeater {
                model: root.scaFailed

                Column {
                  id: checkCard
                  required property var modelData
                  width: parent.width
                  spacing: Style.space(2)

                  Text {
                    text: checkCard.modelData.title || "Untitled check"
                    color: Color.accent
                    font.family: root.bar.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    wrapMode: Text.WordWrap
                    width: parent.width
                  }

                  Text {
                    visible: !!checkCard.modelData.remediation
                    text: checkCard.modelData.remediation || ""
                    color: Qt.darker(root.bar.foreground, 1.3)
                    font.family: root.bar.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                    width: parent.width
                  }
                }
              }

              Text {
                visible: root.scaFailed.length === 0 && root.scaScans.length > 0
                text: "No failed checks in the local database."
                color: Qt.darker(root.bar.foreground, 1.4)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
              }
            }
          }

          // ---------- FIM ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.installed && root.activeTab === 2

            Text {
              visible: !root.fimData || !root.fimData.readable
              text: root.fimData ? Model.errorLabel(root.fimData.error) : "Loading..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Column {
              width: parent.width
              spacing: Style.space(8)
              visible: !!(root.fimData && root.fimData.readable)

              PanelSectionHeader { text: "BASELINE"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
              KeyValueRow { k: "Monitored paths"; v: Model.fieldOrDash(root.fimData ? root.fimData.monitoredCount : null) }

              Column {
                width: parent.width
                spacing: Style.space(3)
                visible: root.fimSample.length > 0

                Text {
                  text: "SAMPLE"
                  color: Qt.darker(root.bar.foreground, 1.6)
                  font.family: root.bar.fontFamily
                  font.pixelSize: Style.font.caption
                  font.letterSpacing: 1.0
                }

                Repeater {
                  model: root.fimSample.slice(0, 50)

                  Text {
                    required property var modelData
                    text: modelData
                    color: root.bar.foreground
                    font.family: root.bar.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideMiddle
                    width: parent.width
                  }
                }
              }
            }
          }

          // ---------- Rootcheck ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.installed && root.activeTab === 3

            PanelSectionHeader { text: "ROOTCHECK"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
            KeyValueRow { k: "Enabled"; v: Model.boolLabel(root.rootcheckData ? root.rootcheckData.enabled : null); vColor: root.statusColor(Model.moduleStatus(root.rootcheckData ? root.rootcheckData.enabled : null)) }
            KeyValueRow { k: "Recent activity (log lines)"; v: Model.fieldOrDash(root.rootcheckData ? root.rootcheckData.recentCount : null) }

            Text {
              text: (root.rootcheckData && root.rootcheckData.error) ? Model.errorLabel(root.rootcheckData.error) : ("Last activity: " + Model.fieldOrDash(root.rootcheckData ? root.rootcheckData.lastLine : null))
              color: Qt.darker(root.bar.foreground, 1.3)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Text {
              text: "Detailed rootkit and anomaly findings are kept on the manager. This panel only shows local agent log activity."
              color: Qt.darker(root.bar.foreground, 1.6)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }
          }

          // ---------- Config ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.installed && root.activeTab === 4

            Text {
              visible: !root.configData || !root.configData.readable
              text: root.configData ? Model.errorLabel(root.configData.error) : "Loading..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Column {
              width: parent.width
              spacing: Style.space(8)
              visible: !!(root.configData && root.configData.readable)

              PanelSectionHeader { text: "FIM DIRECTORIES"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: root.fimDirs.length > 0 }
              Repeater {
                model: root.fimDirs
                KeyValueRow {
                  required property var modelData
                  k: modelData.path
                  v: modelData.realtime ? "realtime" : "scheduled"
                }
              }

              PanelSeparator { foreground: root.bar.foreground; visible: root.logFiles.length > 0 }
              PanelSectionHeader { text: "LOG SOURCES"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: root.logFiles.length > 0 }
              Repeater {
                model: root.logFiles
                KeyValueRow {
                  required property var modelData
                  k: modelData.location
                  v: modelData.format
                }
              }

              PanelSeparator { foreground: root.bar.foreground; visible: root.scaPolicyNames.length > 0 }
              PanelSectionHeader { text: "SCA POLICIES"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: root.scaPolicyNames.length > 0 }
              Repeater {
                model: root.scaPolicyNames
                Text {
                  required property var modelData
                  text: modelData
                  color: root.bar.foreground
                  font.family: root.bar.fontFamily
                  font.pixelSize: Style.font.caption
                  width: parent.width
                  elide: Text.ElideRight
                }
              }

              PanelSeparator { foreground: root.bar.foreground; visible: root.activeResponses.length > 0 }
              PanelSectionHeader { text: "ACTIVE RESPONSE"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: root.activeResponses.length > 0 }
              Repeater {
                model: root.activeResponses
                KeyValueRow {
                  required property var modelData
                  k: modelData.command
                  v: modelData.enabled ? "enabled" : "disabled"
                  vColor: modelData.enabled ? root.bar.foreground : Qt.darker(root.bar.foreground, 1.6)
                }
              }
            }
          }

          // ---------- Logs ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.installed && root.activeTab === 5

            Text {
              visible: !root.logsData || !root.logsData.readable
              text: root.logsData ? Model.errorLabel(root.logsData.error) : "Loading..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Column {
              width: parent.width
              spacing: Style.space(6)
              visible: !!(root.logsData && root.logsData.readable)

              Text {
                text: (root.logsData ? root.logsData.errorCount : 0) + " errors, " + (root.logsData ? root.logsData.warnCount : 0) + " warnings in view"
                color: Qt.darker(root.bar.foreground, 1.4)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
              }

              Repeater {
                model: root.logEntries

                Text {
                  required property var modelData
                  text: modelData.text
                  color: (modelData.level === "ERROR" || modelData.level === "CRITICAL") ? root.bar.urgent : (modelData.level === "WARNING" ? Color.accent : Qt.darker(root.bar.foreground, 1.2))
                  font.family: root.bar.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  width: parent.width
                }
              }
            }
          }

          Item { width: parent.width; height: Style.space(4) }
        }
      }
    }
  }

  // ---------- Reusable rows ----------

  component KeyValueRow: Item {
    property string k: ""
    property string v: ""
    property color vColor: root.bar.foreground
    width: parent.width
    implicitHeight: kText.implicitHeight

    Text {
      id: kText
      text: parent.k
      color: Qt.darker(root.bar.foreground, 1.4)
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width * 0.42
      elide: Text.ElideRight
    }

    Text {
      text: parent.v
      color: parent.vColor
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width * 0.58
      horizontalAlignment: Text.AlignRight
      elide: Text.ElideRight
    }
  }

  component TabButtonItem: Rectangle {
    id: tabButton
    property string label: ""
    property int index: 0
    width: tabLabel.implicitWidth + Style.space(16)
    height: tabLabel.implicitHeight + Style.space(8)
    radius: Style.cornerRadius / 2
    color: root.activeTab === index ? Qt.darker(root.bar.foreground, 4) : "transparent"

    Text {
      id: tabLabel
      anchors.centerIn: parent
      text: tabButton.label
      color: root.activeTab === tabButton.index ? root.bar.foreground : Qt.darker(root.bar.foreground, 1.6)
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: root.activeTab === tabButton.index
    }

    MouseArea {
      anchors.fill: parent
      cursorShape: Qt.PointingHandCursor
      onClicked: root.activeTab = tabButton.index
    }
  }
}
