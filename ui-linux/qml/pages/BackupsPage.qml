import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    title: "Backups"

    property var backupsList: []
    property string searchText: ""

    Component.onCompleted: {
        reloadBackups()
    }

    // Auto-refresh when page becomes visible (tab switch)
    onVisibleChanged: {
        if (visible) {
            reloadBackups()
        }
    }

    function reloadBackups() {
        backupsList = backend ? backend.listBackups() : []
    }

    function filteredBackups() {
        if (searchText === "") return backupsList
        var needle = searchText.toLowerCase()
        var result = []
        for (var i = 0; i < backupsList.length; i++) {
            var backup = backupsList[i]
            var name = backend ? backend.getAppName(backup.appId).toLowerCase() : ""
            if (String(backup.appId).indexOf(needle) >= 0 || name.indexOf(needle) >= 0) {
                result.push(backup)
            }
        }
        return result
    }

    Connections {
        target: backend
        function onAppNamesResolved() {
            // Force refresh to pick up new names
            reloadBackups()
        }
        function onAppsChanged() {
            // Refresh after restore/delete operations
            reloadBackups()
        }
    }

    // Restore confirmation dialog
    Dialog {
        id: restoreDialog
        title: "Restore Backup"
        modal: true
        standardButtons: Dialog.NoButton
        anchors.centerIn: parent
        width: Math.min(parent.width - 80, 480)

        property var targetBackup: null
        property string resultMessage: ""
        property bool isRestoring: false

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "Restore backup for '" + (backend ? backend.getAppName(restoreDialog.targetBackup ? restoreDialog.targetBackup.appId : 0) : "Unknown") + "'?"
                font.bold: true
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                visible: !restoreDialog.isRestoring && restoreDialog.resultMessage === ""
            }

            Label {
                text: "ID: " + (restoreDialog.targetBackup ? restoreDialog.targetBackup.appId : "") + "  -  " + (restoreDialog.targetBackup ? restoreDialog.targetBackup.fileCount : "") + " file(s), " + (restoreDialog.targetBackup ? restoreDialog.targetBackup.sizeFormatted : "")
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                opacity: 0.7
                visible: !restoreDialog.isRestoring && restoreDialog.resultMessage === ""
            }

            Label {
                text: "Created: " + (restoreDialog.targetBackup ? restoreDialog.targetBackup.timestamp : "")
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                opacity: 0.7
                visible: !restoreDialog.isRestoring && restoreDialog.resultMessage === ""
            }

            Label {
                text: "This will overwrite any existing save data for this app."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                visible: !restoreDialog.isRestoring && restoreDialog.resultMessage === ""
            }

            // Restoring state
            Label {
                text: "Restoring..."
                visible: restoreDialog.isRestoring
                Layout.alignment: Qt.AlignHCenter
            }

            // Result message
            Label {
                text: restoreDialog.resultMessage
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                visible: restoreDialog.resultMessage !== ""
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 4

                Item { Layout.fillWidth: true }

                Button {
                    text: restoreDialog.resultMessage !== "" ? "Close" : "Cancel"
                    onClicked: {
                        restoreDialog.resultMessage = ""
                        restoreDialog.isRestoring = false
                        restoreDialog.close()
                    }
                }

                Button {
                    text: "Restore"
                    visible: !restoreDialog.isRestoring && restoreDialog.resultMessage === ""
                    onClicked: {
                        if (!backend || !restoreDialog.targetBackup) {
                            restoreDialog.resultMessage = "No backup selected"
                            return
                        }
                        restoreDialog.isRestoring = true
                        var result = backend.restoreBackup(restoreDialog.targetBackup.path)
                        restoreDialog.isRestoring = false
                        restoreDialog.resultMessage = result
                        backend.refreshStatus()
                    }
                }
            }
        }
    }

    // Delete backup confirmation dialog
    Dialog {
        id: deleteBackupDialog
        title: "Delete Backup"
        modal: true
        standardButtons: Dialog.NoButton
        anchors.centerIn: parent
        width: Math.min(parent.width - 80, 400)

        property var targetBackup: null
        property int countdown: 3
        property bool canDelete: false

        Timer {
            id: deleteCountdownTimer
            interval: 1000
            repeat: true
            onTriggered: {
                deleteBackupDialog.countdown--
                if (deleteBackupDialog.countdown <= 0) {
                    deleteCountdownTimer.stop()
                    deleteBackupDialog.canDelete = true
                }
            }
        }

        onOpened: {
            countdown = 3
            canDelete = false
            deleteCountdownTimer.start()
        }

        onClosed: {
            deleteCountdownTimer.stop()
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "Delete this backup permanently?"
                font.bold: true
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Label {
                text: deleteBackupDialog.targetBackup ? (backend ? backend.getAppName(deleteBackupDialog.targetBackup.appId) : "Unknown") + " (" + deleteBackupDialog.targetBackup.appId + ")" : ""
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Label {
                text: deleteBackupDialog.targetBackup ? deleteBackupDialog.targetBackup.fileCount + " file(s), " + deleteBackupDialog.targetBackup.sizeFormatted : ""
                opacity: 0.7
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Label {
                text: "This cannot be undone."
                opacity: 0.7
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 4

                Item { Layout.fillWidth: true }

                Button {
                    text: "Cancel"
                    onClicked: deleteBackupDialog.close()
                }

                Button {
                    text: deleteBackupDialog.canDelete ? "Delete" : "Delete (" + deleteBackupDialog.countdown + ")"
                    enabled: deleteBackupDialog.canDelete
                    onClicked: {
                        if (deleteBackupDialog.targetBackup && backend) {
                            backend.deleteBackup(deleteBackupDialog.targetBackup.path)
                            deleteBackupDialog.close()
                            reloadBackups()
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
                text: "Backups"
                font.pointSize: 16
                font.bold: true
                Layout.leftMargin: 20
            }

            Label {
                text: "Save data backups created before deletion. Restore to recover deleted saves."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                opacity: 0.7
            }

            // Search bar
            TextField {
                id: backupSearchField
                placeholderText: "Search by name or App ID..."
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                onTextChanged: searchText = text
            }

            // Backups list
            Repeater {
                model: filteredBackups()

                Frame {
                    Layout.fillWidth: true
                    Layout.leftMargin: 20
                    Layout.rightMargin: 20

                    RowLayout {
                        width: parent.width
                        spacing: 12

                        Image {
                            source: backend ? backend.getAppHeaderUrl(modelData.appId) : ""
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
                            Layout.maximumWidth: 350
                            spacing: 4

                            Label {
                                text: backend ? backend.getAppName(modelData.appId) : "Unknown"
                                font.bold: true
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }

                            Label {
                                text: "ID: " + modelData.appId + "  -  " + modelData.fileCount + " file(s)  -  " + modelData.sizeFormatted
                                opacity: 0.7
                            }

                            Label {
                                text: modelData.timestamp
                                opacity: 0.5
                                font.pointSize: 9
                            }
                        }

                        Item { Layout.fillWidth: true }

                        Button {
                            text: "Restore"
                            onClicked: {
                                restoreDialog.targetBackup = modelData
                                restoreDialog.resultMessage = ""
                                restoreDialog.isRestoring = false
                                restoreDialog.open()
                            }
                        }

                        Button {
                            icon.name: "edit-delete"
                            text: "Delete"
                            display: AbstractButton.TextBesideIcon
                            onClicked: {
                                deleteBackupDialog.targetBackup = modelData
                                deleteBackupDialog.open()
                            }
                        }
                    }
                }
            }

            // Empty state
            Label {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 40
                visible: backupsList.length === 0
                text: "No backups found.\n\nBackups are created automatically when you delete app data."
                horizontalAlignment: Text.AlignHCenter
                opacity: 0.5
            }

            // No search results
            Label {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 40
                visible: backupsList.length > 0 && filteredBackups().length === 0 && searchText !== ""
                text: "No backups match \"" + searchText + "\""
                horizontalAlignment: Text.AlignHCenter
                opacity: 0.5
            }

            // Status bar
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                Label {
                    text: backupsList.length + " backup(s)"
                    opacity: 0.6
                }
                Item { Layout.fillWidth: true }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
