import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    title: "Apps"

    property var appsList: []
    property var filteredLocalApps: []
    property var filteredRemoteApps: []
    property string searchText: ""
    property string statusText: ""

    Component.onCompleted: {
        reloadApps()
        if (backend) backend.fetchRemoteApps()
    }

    function reloadApps() {
        appsList = backend ? backend.getAppDetails() : []
        updateFilteredLists()
    }

    function updateFilteredLists() {
        var localCount = 0
        var remoteCount = 0
        var localResult = []
        var remoteResult = []
        var needle = searchText.toLowerCase()

        for (var i = 0; i < appsList.length; i++) {
            var app = appsList[i]
            var matches = (needle === "") ||
                          String(app.appId).indexOf(needle) >= 0 ||
                          app.name.toLowerCase().indexOf(needle) >= 0

            if (app.isLocal) {
                localCount++
                if (matches) localResult.push(app)
            }
            if (app.isRemote && !app.isLocal) {
                remoteCount++
                if (matches) remoteResult.push(app)
            }
        }

        localResult.sort(function(a, b) { return a.appId - b.appId })
        remoteResult.sort(function(a, b) { return a.appId - b.appId })

        filteredLocalApps = localResult
        filteredRemoteApps = remoteResult
        statusText = localCount + " local, " + remoteCount + " remote"
    }

    onSearchTextChanged: updateFilteredLists()

    function formatProviderName(name) {
        if (backend) return backend.providerLabel(name)
        return name
    }

    Connections {
        target: backend
        function onAppNamesResolved() {
            reloadApps()
        }
        function onAppsChanged() {
            reloadApps()
        }
        function onRemoteAppsFetched() {
            reloadApps()
        }
    }

    Dialog {
        id: deleteDialog
        title: "Delete App Data"
        modal: true
        standardButtons: Dialog.NoButton
        anchors.centerIn: parent
        width: Math.min(parent.width - 80, 480)

        property var targetApp: null
        property int countdown: 5
        property bool canDelete: false

        Timer {
            id: countdownTimer
            interval: 1000
            repeat: true
            onTriggered: {
                deleteDialog.countdown--
                if (deleteDialog.countdown <= 0) {
                    countdownTimer.stop()
                    deleteDialog.canDelete = true
                }
            }
        }

        onOpened: {
            countdown = 5
            canDelete = false
            countdownTimer.start()
        }

        onClosed: {
            countdownTimer.stop()
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "Delete all saves for '" + (deleteDialog.targetApp ? deleteDialog.targetApp.name : "") + "' (" + (deleteDialog.targetApp ? deleteDialog.targetApp.appId : "") + ")"
                font.bold: true
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Label {
                text: "This will permanently delete:"
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            ColumnLayout {
                spacing: 2
                Layout.leftMargin: 12

                Label {
                    text: "• " + (deleteDialog.targetApp ? deleteDialog.targetApp.fileCount : "") + " file(s) (" + (deleteDialog.targetApp ? deleteDialog.targetApp.sizeFormatted : "") + ") from local CloudRedirect storage"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    opacity: 0.8
                }

                Label {
                    text: "• Steam userdata directory for this app"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    opacity: 0.8
                }
            }

            Label {
                text: {
                    var provider = backend ? backend.providerName : "local"
                    if (provider === "gdrive" || provider === "onedrive" || provider === "r2")
                        return "The cloud copy in " + formatProviderName(provider) + " will also be deleted."
                    return ""
                }
                visible: text !== ""
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                opacity: 0.7
            }

            Label {
                text: "The data will be re-downloaded from the cloud on next game launch. A backup will be created before deletion."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                opacity: 0.7
            }

            Label {
                text: "This cannot be undone."
                font.bold: true
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 4

                Item { Layout.fillWidth: true }

                Button {
                    text: "Cancel"
                    onClicked: deleteDialog.close()
                }

                Button {
                    text: deleteDialog.canDelete ? "Delete All Saves" : "Delete (" + deleteDialog.countdown + ")"
                    enabled: deleteDialog.canDelete
                    onClicked: {
                        if (backend && deleteDialog.targetApp) {
                            backend.deleteAppData(deleteDialog.targetApp.appId)
                        }
                        deleteDialog.close()
                        reloadApps()
                    }
                }
            }
        }
    }

    // Orphan results dialog
    Dialog {
        id: orphanDialog
        title: "Orphan Scan Results"
        modal: true
        standardButtons: Dialog.Ok
        anchors.centerIn: parent
        width: Math.min(parent.width - 80, 480)

        property var results: []

        ColumnLayout {
            anchors.fill: parent
            spacing: 8

            Label {
                text: orphanDialog.results.length === 0
                      ? "No orphan blobs found. Storage is clean."
                      : orphanDialog.results.length + " app(s) with orphan blobs:"
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Repeater {
                model: orphanDialog.results

                Frame {
                    Layout.fillWidth: true

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 2

                        Label {
                            text: modelData.name + " (" + modelData.appId + ")"
                            font.bold: true
                        }
                        Label {
                            text: modelData.orphanCount + " orphan file(s), " + modelData.orphanSizeFormatted
                            opacity: 0.7
                        }
                    }
                }
            }
        }
    }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth

        ColumnLayout {
            width: parent.width
            spacing: 12

            Item { height: 8 }

            Label {
                text: "Apps"
                font.pointSize: 16
                font.bold: true
                Layout.leftMargin: 20
            }

            Label {
                text: "Cloud saves managed by CloudRedirect. Search by name or App ID."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                opacity: 0.7
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                spacing: 8

                TextField {
                    id: searchField
                    placeholderText: "Search by name or App ID..."
                    Layout.fillWidth: true
                    onTextChanged: searchText = text
                }

                Button {
                    text: "Scan Orphans"
                    onClicked: {
                        var results = backend ? backend.scanOrphans() : []
                        orphanDialog.results = results
                        orphanDialog.open()
                    }
                }

                Button {
                    text: "Refresh"
                    onClicked: {
                        if (backend) {
                            backend.refreshStatus()
                            backend.fetchRemoteApps()
                        }
                        reloadApps()
                    }
                }
            }

            // Local Saves section
            Label {
                text: "Local Saves"
                font.pointSize: 13
                font.bold: true
                Layout.leftMargin: 20
                Layout.topMargin: 8
            }

            Repeater {
                model: filteredLocalApps

                Frame {
                    Layout.fillWidth: true
                    Layout.leftMargin: 20
                    Layout.rightMargin: 20

                    RowLayout {
                        width: parent.width
                        spacing: 12

                        Image {
                            source: modelData.headerUrl
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
                                text: modelData.name
                                font.bold: true
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                            Label {
                                text: "ID: " + modelData.appId + "  •  " + modelData.fileCount + " file(s)  •  " + modelData.sizeFormatted + (modelData.saveRoot ? "  •  " + modelData.saveRoot : "")
                                opacity: 0.7
                            }
                        }

                        Item { Layout.fillWidth: true }

                        Button {
                            icon.name: "edit-delete"
                            text: "Delete"
                            display: AbstractButton.TextBesideIcon
                            onClicked: {
                                deleteDialog.targetApp = modelData
                                deleteDialog.open()
                            }
                        }
                    }
                }
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                visible: filteredLocalApps.length === 0 && searchText === ""
                text: "No local saves found."
                opacity: 0.5
            }

            Label {
                text: "Remote Saves"
                font.pointSize: 13
                font.bold: true
                Layout.leftMargin: 20
                Layout.topMargin: 8
                visible: filteredRemoteApps.length > 0
            }

            Label {
                text: "Apps with save data in cloud storage that are not downloaded locally."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                opacity: 0.7
                visible: filteredRemoteApps.length > 0
            }

            Repeater {
                model: filteredRemoteApps

                Frame {
                    Layout.fillWidth: true
                    Layout.leftMargin: 20
                    Layout.rightMargin: 20

                    RowLayout {
                        width: parent.width
                        spacing: 12

                        Image {
                            source: modelData.headerUrl
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
                                text: modelData.name
                                font.bold: true
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                            Label {
                                text: "ID: " + modelData.appId + "  •  Account: " + (backend ? backend.accountName : "Unknown")
                                opacity: 0.7
                            }
                            Label {
                                text: "Not downloaded locally  •  Will download on next game launch"
                                opacity: 0.5
                            }
                        }

                        Item { Layout.fillWidth: true }
                    }
                }
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                visible: filteredRemoteApps.length === 0 && searchText === ""
                text: "No remote-only saves found."
                opacity: 0.5
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 40
                visible: appsList.length === 0
                text: "No apps found.\n\nInstall games via SLSsteam to see them here."
                horizontalAlignment: Text.AlignHCenter
                opacity: 0.5
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 40
                visible: appsList.length > 0 && filteredLocalApps.length === 0 && filteredRemoteApps.length === 0 && searchText !== ""
                text: "No apps match \"" + searchText + "\""
                horizontalAlignment: Text.AlignHCenter
                opacity: 0.5
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                Label {
                    text: statusText
                    opacity: 0.6
                }
                Item { Layout.fillWidth: true }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
