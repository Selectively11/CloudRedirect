import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    id: page
    title: "Migration"

    // Provider options for the source/dest combos (cloud providers only).
    property var providers: [
        { value: "gdrive",   name: "Google Drive" },
        { value: "onedrive", name: "OneDrive" },
        { value: "r2",       name: "Cloudflare R2" },
        { value: "s3",       name: "S3 Compatible" }
    ]

    // UI phase: "config" | "progress" | "result"
    property string phase: "config"

    // Scan state.
    property bool scanning: false
    property var sourceApps: []          // [{ appId, accountId }]
    property string validationText: ""
    property bool validationError: false

    // Progress state.
    property bool indeterminate: true
    property int progDone: 0
    property int progTotal: 0
    property string progStatus: ""
    property string progDetail: ""
    property bool cancelling: false
    property double startMs: 0

    // Result state.
    property var lastResult: null

    function providerLabel(key) {
        // Labels come from the backend so they stay consistent across pages.
        if (backend) return backend.providerLabel(key)
        return key
    }

    function srcKey() {
        return (sourceCombo.currentIndex >= 0 && sourceCombo.currentIndex < providers.length)
            ? providers[sourceCombo.currentIndex].value : ""
    }
    function dstKey() {
        return (destCombo.currentIndex >= 0 && destCombo.currentIndex < providers.length)
            ? providers[destCombo.currentIndex].value : ""
    }

    function setValidation(text, isError) {
        validationText = text
        validationError = isError
    }

    function formatBytes(b) {
        if (b < 1024) return b + " B"
        if (b < 1024 * 1024) return (b / 1024.0).toFixed(1) + " KB"
        if (b < 1024 * 1024 * 1024) return (b / (1024.0 * 1024)).toFixed(1) + " MB"
        return (b / (1024.0 * 1024 * 1024)).toFixed(2) + " GB"
    }

    // Debounce scans; coalesce a burst of combo changes into one scan.
    Timer {
        id: scanDebounce
        interval: 150
        repeat: false
        onTriggered: page.runScan()
    }

    function validateAndScan() {
        var src = srcKey()
        var dst = dstKey()
        sourceApps = []
        if (!src || !dst) { setValidation("", false); scanDebounce.stop(); return }
        if (src === dst) {
            setValidation("Source and destination must be different providers.", true)
            scanDebounce.stop()
            return
        }
        setValidation("", false)
        scanDebounce.restart()
    }

    function runScan() {
        var src = srcKey()
        var dst = dstKey()
        if (!src || !dst || src === dst) return
        if (backend) backend.scanProvider(src)
    }

    function accountCount() {
        var seen = {}
        var n = 0
        for (var i = 0; i < sourceApps.length; i++) {
            var a = sourceApps[i].accountId
            if (a && !seen[a]) { seen[a] = true; n++ }
        }
        return n
    }

    Component.onCompleted: {
        // Pre-select the active cloud provider as source, else the first.
        var active = backend ? backend.activeProvider() : ""
        var srcIdx = 0
        for (var i = 0; i < providers.length; i++)
            if (providers[i].value === active) { srcIdx = i; break }
        sourceCombo.currentIndex = srcIdx
        destCombo.currentIndex = (srcIdx === 0) ? 1 : 0
        validateAndScan()
    }

    Connections {
        target: backend

        function onMigrationScanStarted() {
            page.scanning = true
            page.sourceApps = []
        }

        function onMigrationScanFinished(apps, error) {
            page.scanning = false
            if (error && error.length > 0) {
                page.setValidation("Scan failed: " + error, true)
                page.sourceApps = []
                return
            }
            page.sourceApps = apps
            if (apps.length === 0)
                page.setValidation("No cloud data found on source provider.", true)
            else
                page.setValidation("", false)
        }

        // App names/art resolved -- rebind the list so cards refresh.
        function onAppNamesResolved() {
            var tmp = page.sourceApps
            page.sourceApps = []
            page.sourceApps = tmp
        }

        function onMigrationStatus(message, done, total, found) {
            page.indeterminate = true
            page.progStatus = message
            var parts = []
            if (total > 0) parts.push("Account " + Math.max(done, 0) + " / " + total)
            if (found > 0) parts.push(found + " file(s) found")
            page.progDetail = parts.join("  \u2022  ")
        }

        function onMigrationStarted(total) {
            page.indeterminate = false
            page.progTotal = total
            page.progDone = 0
        }

        function onMigrationProgress(done, total, file, totalBytes) {
            page.indeterminate = false
            page.progDone = done
            page.progTotal = total
            page.progStatus = done + " / " + total + " files"
            page.progDetail = file
        }

        function onMigrationFinished(result) {
            page.lastResult = result
            page.phase = "result"
        }
    }

    // ── Config phase ────────────────────────────────────────────────────
    // No outer ScrollView: the games list scrolls itself; everything else fits.
    ColumnLayout {
        id: configColumn
        anchors.fill: parent
        spacing: 12
        visible: page.phase === "config"

        Item { height: 8 }

            Label {
                text: "Migrate Cloud Saves"
                font.pointSize: 16
                font.bold: true
                Layout.leftMargin: 20
            }

            Label {
                text: "Copy all your cloud saves from one provider to another. "
                    + "The destination becomes your active provider when the migration succeeds."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                opacity: 0.7
            }

            // Active provider banner.
            Frame {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                visible: backend && backend.activeProvider() !== "" && backend.activeProvider() !== "local"

                RowLayout {
                    width: parent.width
                    spacing: 8
                    Label { text: "Currently active:"; opacity: 0.7 }
                    Label {
                        text: backend ? page.providerLabel(backend.activeProvider()) : ""
                        font.bold: true
                    }
                    Item { Layout.fillWidth: true }
                }
            }

            Frame {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                ColumnLayout {
                    width: parent.width
                    spacing: 12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            Label { text: "From (source)"; font.bold: true }
                            ComboBox {
                                id: sourceCombo
                                Layout.fillWidth: true
                                model: providers.map(function(p) { return p.name })
                                onCurrentIndexChanged: page.validateAndScan()
                            }
                        }

                        Label {
                            text: "\u2192"
                            font.pointSize: 18
                            Layout.alignment: Qt.AlignBottom
                            Layout.bottomMargin: 4
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            Label { text: "To (destination)"; font.bold: true }
                            ComboBox {
                                id: destCombo
                                Layout.fillWidth: true
                                model: providers.map(function(p) { return p.name })
                                onCurrentIndexChanged: page.validateAndScan()
                            }
                        }
                    }

                    Label {
                        text: page.validationText
                        visible: page.validationText !== ""
                        color: page.validationError ? "#E04040" : palette.text
                        opacity: page.validationError ? 1.0 : 0.7
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            // Scan loading.
            RowLayout {
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                visible: page.scanning
                spacing: 8
                BusyIndicator { running: page.scanning; implicitWidth: 24; implicitHeight: 24 }
                Label { text: "Scanning " + page.providerLabel(page.srcKey()) + "..."; opacity: 0.7 }
            }

            // Source apps header.
            Label {
                visible: page.sourceApps.length > 0 && !page.scanning
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                text: {
                    var n = page.accountCount()
                    var base = page.sourceApps.length + " game(s) on " + page.providerLabel(page.srcKey())
                    if (n > 1) base = page.sourceApps.length + " game(s) across " + n + " accounts on " + page.providerLabel(page.srcKey())
                    return base + ":"
                }
                font.bold: true
            }

            // Scanned games; clamped and independently scrollable so Start stays visible.
            Frame {
                visible: page.sourceApps.length > 0 && !page.scanning
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                padding: 4

                // ~72px per card; show up to 3 before scrolling.
                readonly property int rowHeight: 72
                readonly property int maxVisibleRows: 3

                Layout.preferredHeight: Math.min(page.sourceApps.length, maxVisibleRows) * rowHeight
                    + topPadding + bottomPadding

                ListView {
                    id: gamesList
                    anchors.fill: parent
                    clip: true
                    model: page.sourceApps
                    spacing: 0
                    boundsBehavior: Flickable.StopAtBounds
                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                    delegate: ItemDelegate {
                        width: gamesList.width
                        height: 72
                        hoverEnabled: false

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 8
                            anchors.rightMargin: 8
                            spacing: 12

                            Image {
                                source: backend ? backend.getAppHeaderUrl(parseInt(modelData.appId)) : ""
                                Layout.preferredWidth: 120
                                Layout.preferredHeight: 56
                                fillMode: Image.PreserveAspectFit
                                asynchronous: true

                                Rectangle {
                                    anchors.fill: parent
                                    color: Qt.rgba(0.5, 0.5, 0.5, 0.15)
                                    visible: parent.status !== Image.Ready
                                    radius: 2
                                    Label {
                                        anchors.centerIn: parent
                                        text: String(modelData.appId)
                                        opacity: 0.4
                                        font.pointSize: 9
                                    }
                                }
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                Layout.maximumWidth: 450
                                spacing: 4
                                Label {
                                    text: backend ? backend.getAppName(parseInt(modelData.appId)) : ("App " + modelData.appId)
                                    font.bold: true
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                Label {
                                    text: "ID: " + modelData.appId
                                        + (modelData.accountId ? "  \u2022  Account: " + modelData.accountId : "")
                                    opacity: 0.7
                                }
                            }

                            Item { Layout.fillWidth: true }
                        }
                    }
                }
            }

            Item { Layout.fillHeight: true; Layout.minimumHeight: 8 }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                Layout.bottomMargin: 12

                Item { Layout.fillWidth: true }

                Button {
                    text: "Start Migration"
                    highlighted: true
                    enabled: !page.scanning && page.sourceApps.length > 0 && page.srcKey() !== page.dstKey()
                    onClicked: page.beginMigration()
                }
            }
    }

    // ── Progress phase ──────────────────────────────────────────────────
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 16
        visible: page.phase === "progress"

        Item { Layout.fillHeight: true }

        Label {
            text: page.providerLabel(page.srcKey()) + "  \u2192  " + page.providerLabel(page.dstKey())
            font.pointSize: 15
            font.bold: true
            Layout.alignment: Qt.AlignHCenter
        }

        ProgressBar {
            Layout.fillWidth: true
            indeterminate: page.indeterminate
            from: 0
            to: page.progTotal > 0 ? page.progTotal : 1
            value: Math.min(page.progDone, page.progTotal)
        }

        Label {
            text: page.progStatus
            Layout.alignment: Qt.AlignHCenter
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
        }

        Label {
            text: page.progDetail
            visible: page.progDetail !== ""
            opacity: 0.6
            elide: Text.ElideMiddle
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
        }

        Item { Layout.fillHeight: true }

        Button {
            text: page.cancelling ? "Cancelling..." : "Cancel"
            enabled: !page.cancelling
            Layout.alignment: Qt.AlignHCenter
            onClicked: {
                page.cancelling = true
                if (backend) backend.cancelMigration()
            }
        }
    }

    // ── Result phase ────────────────────────────────────────────────────
    ColumnLayout {
        id: resultLayout
        anchors.fill: parent
        anchors.margins: 20
        spacing: 16
        visible: page.phase === "result"

        Item { Layout.fillHeight: true }

        property var r: page.lastResult ? page.lastResult : ({})
        property bool cancelled: r.cancelled === true
        property bool hasError: r.error !== undefined && r.error !== ""
        property bool hasFailed: (r.failed ? r.failed : 0) > 0

        Frame {
            id: resultBox
            Layout.fillWidth: true

            // Only warn/error states get a tint; success is plain.
            property color accent: resultLayout.cancelled || resultLayout.hasFailed
                ? "#C88A2C"
                : (resultLayout.hasError ? "#C43B3B" : "transparent")
            property bool tinted: resultLayout.cancelled || resultLayout.hasFailed || resultLayout.hasError

            background: Rectangle {
                color: resultBox.tinted
                    ? Qt.rgba(resultBox.accent.r, resultBox.accent.g, resultBox.accent.b, 0.16)
                    : "transparent"
                border.color: resultBox.tinted
                    ? Qt.rgba(resultBox.accent.r, resultBox.accent.g, resultBox.accent.b, 0.5)
                    : Qt.rgba(palette.text.r, palette.text.g, palette.text.b, 0.2)
                border.width: 1
                radius: 6
            }

            ColumnLayout {
                width: parent.width
                spacing: 8

                Label {
                    text: {
                        var p = resultLayout
                        if (p.cancelled) return "Migration cancelled"
                        if (p.hasError) return "Migration failed"
                        if (p.hasFailed) return "Completed with errors"
                        return "Migration complete"
                    }
                    font.pointSize: 14
                    font.bold: true
                }

                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: {
                        var p = resultLayout
                        var r = p.r
                        if (p.cancelled)
                            return "Cancelled after migrating " + (r.migrated ? r.migrated : 0) + " file(s)."
                        if (p.hasError)
                            return r.error
                        var s = "Migrated: " + (r.migrated ? r.migrated : 0)
                              + "  |  Skipped: " + (r.skipped ? r.skipped : 0)
                        if (p.hasFailed) s += "  |  Failed: " + r.failed
                        s += "\nTotal transferred: " + page.formatBytes(r.totalBytes ? r.totalBytes : 0)
                        if (p.hasFailed && r.lastError) s += "\nLast error: " + r.lastError
                        return s
                    }
                }

                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    visible: resultLayout.r.switched === true
                    opacity: 0.85
                    text: "Now using " + page.providerLabel(page.dstKey()) + " as your active provider."
                }
            }
        }

        Item { Layout.fillHeight: true }

        RowLayout {
            Layout.fillWidth: true
            Item { Layout.fillWidth: true }

            Button {
                text: "Retry"
                visible: resultLayout.hasFailed && !resultLayout.hasError
                onClicked: page.beginMigration()
            }

            Button {
                text: "Back"
                highlighted: true
                onClicked: {
                    page.phase = "config"
                    page.setValidation("", false)
                    page.validateAndScan()
                }
            }
        }
    }

    // ── Actions ─────────────────────────────────────────────────────────
    function beginMigration() {
        var src = srcKey()
        var dst = dstKey()
        if (!src || !dst || src === dst) return
        if (!backend) return

        // Light pre-flight credential checks (CLI does the real auth test).
        var s = backend.checkProviderCredentials(src)
        if (!s.ok) {
            setValidation("Source (" + providerLabel(src) + "): " + s.message, true)
            return
        }
        var d = backend.checkProviderCredentials(dst)
        if (!d.ok) {
            setValidation("Destination (" + providerLabel(dst) + "): " + d.message, true)
            return
        }

        // Reset progress state and switch phase.
        indeterminate = true
        progDone = 0
        progTotal = 0
        progStatus = "Starting..."
        progDetail = ""
        cancelling = false
        lastResult = null
        phase = "progress"

        backend.startMigration(src, dst)
    }
}
