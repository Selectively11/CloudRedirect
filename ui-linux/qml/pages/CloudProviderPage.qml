import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

Page {
    title: "Cloud Provider"

    property var providers: [
        { value: "local", name: "Local Storage", desc: "Saves stored in Steam directory only. No cloud sync." },
        { value: "folder", name: "Custom Folder", desc: "Sync to a network share or other local path." },
        { value: "gdrive", name: "Google Drive", desc: "Sync saves to your Google Drive account." },
        { value: "onedrive", name: "OneDrive", desc: "Sync saves to your Microsoft OneDrive account." }
    ]

    property bool comboReady: false
    
    // Track auth state locally so bindings update when settingsChanged fires
    property bool gdriveAuth: backend ? backend.isProviderAuthenticated("gdrive") : false
    property bool onedriveAuth: backend ? backend.isProviderAuthenticated("onedrive") : false
    
    function refreshAuthState() {
        gdriveAuth = backend ? backend.isProviderAuthenticated("gdrive") : false
        onedriveAuth = backend ? backend.isProviderAuthenticated("onedrive") : false
    }

    function currentProviderIndex() {
        var name = (backend && backend.providerName) ? backend.providerName : "local"
        for (var i = 0; i < providers.length; i++) {
            if (providers[i].value === name) return i
        }
        return 0
    }
    
    // Bounds-safe provider lookup
    function currentProvider() {
        var idx = providerCombo.currentIndex
        if (idx >= 0 && idx < providers.length) return providers[idx]
        return providers[0]  // fallback to local
    }

    FolderDialog {
        id: folderDialog
        title: "Select Sync Folder"
        onAccepted: {
            // Convert file:// URL to path
            var path = selectedFolder.toString()
            if (path.startsWith("file://")) {
                path = path.substring(7)
            }
            if (backend) backend.syncFolderPath = path
        }
    }

    Connections {
        target: oauth
        function onStatusMessage(msg) {
            statusText.text = msg
            authUrlBox.visible = false
        }
        function onAuthSucceeded(provider) {
            statusText.text = "Authentication successful!"
            authUrlBox.visible = false
            backend.refreshStatus()
            refreshAuthState()
        }
        function onAuthFailed(provider, error) {
            statusText.text = "Error: " + error
            authUrlBox.visible = false
        }
        function onBrowserFailed(url) {
            statusText.text = "Could not open browser. Copy the URL below and paste it in your browser:"
            authUrlField.text = url
            authUrlBox.visible = true
        }
    }
    
    Connections {
        target: backend
        function onSettingsChanged() {
            refreshAuthState()
            // Keep combo in sync with backend
            if (comboReady) {
                var expected = currentProviderIndex()
                if (providerCombo.currentIndex !== expected)
                    providerCombo.currentIndex = expected
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
                text: "Cloud Provider"
                font.pointSize: 16
                font.bold: true
                Layout.leftMargin: 20
            }

            Label {
                text: "Choose where CloudRedirect syncs your save files."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                opacity: 0.7
            }

            Frame {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                ColumnLayout {
                    width: parent.width
                    spacing: 8

                    Label {
                        text: "Provider"
                        font.bold: true
                    }

                    ComboBox {
                        id: providerCombo
                        Layout.fillWidth: true
                        model: providers.map(p => p.name)
                        Component.onCompleted: {
                            comboReady = true
                            currentIndex = currentProviderIndex()
                        }
                        onCurrentIndexChanged: {
                            if (comboReady && currentIndex >= 0 && backend) {
                                backend.providerName = providers[currentIndex].value
                            }
                        }
                    }

                    Label {
                        text: currentProvider().desc
                        opacity: 0.7
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            Frame {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                visible: currentProvider().value !== "local"

                ColumnLayout {
                    width: parent.width
                    spacing: 8

                    Label {
                        text: "Status"
                        font.bold: true
                    }
                    Label {
                        text: {
                            var provider = currentProvider()
                            if (provider.value === "folder") {
                                if (backend && backend.syncFolderPath)
                                    return "Syncing to " + backend.syncFolderPath
                                return "No folder configured"
                            }
                            if (provider.value === "gdrive" && gdriveAuth) return "Authenticated"
                            if (provider.value === "onedrive" && onedriveAuth) return "Authenticated"
                            return "Not authenticated"
                        }
                        opacity: 0.7
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            Frame {
                visible: currentProvider().value === "folder"
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                ColumnLayout {
                    width: parent.width
                    spacing: 8

                    Label {
                        text: "Sync Folder"
                        font.bold: true
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8

                        TextField {
                            id: folderPathField
                            Layout.fillWidth: true
                            placeholderText: "/path/to/sync/folder"
                            text: backend ? backend.syncFolderPath : ""
                            onEditingFinished: { if (backend) backend.syncFolderPath = text }
                        }

                        Button {
                            text: "Browse..."
                            onClicked: folderDialog.open()
                        }
                    }

                    Label {
                        text: "Choose a folder on a network share, external drive, or cloud-synced directory (e.g., Dropbox, Syncthing)."
                        opacity: 0.6
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                        font.pointSize: 9
                    }
                }
            }

            Button {
                visible: currentProvider().value === "gdrive"
                Layout.leftMargin: 20
                text: gdriveAuth ? "Re-authenticate" : "Sign in with Google"
                highlighted: !gdriveAuth
                onClicked: {
                    if (backend && oauth) {
                        let tokenPath = backend.providerPath || backend.defaultTokenPath("gdrive")
                        oauth.startAuth("gdrive", tokenPath)
                    }
                }
            }

            Button {
                visible: currentProvider().value === "onedrive"
                Layout.leftMargin: 20
                text: onedriveAuth ? "Re-authenticate" : "Sign in with Microsoft"
                highlighted: !onedriveAuth
                onClicked: {
                    if (backend && oauth) {
                        let tokenPath = backend.providerPath || backend.defaultTokenPath("onedrive")
                        oauth.startAuth("onedrive", tokenPath)
                    }
                }
            }

            Label {
                id: statusText
                text: ""
                visible: text !== ""
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                opacity: 0.7
            }

            RowLayout {
                id: authUrlBox
                visible: false
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                spacing: 8

                TextField {
                    id: authUrlField
                    readOnly: true
                    selectByMouse: true
                    Layout.fillWidth: true
                    font.pointSize: 8
                }

                Button {
                    text: "Copy"
                    onClicked: {
                        authUrlField.selectAll()
                        authUrlField.copy()
                        authUrlField.deselect()
                    }
                }
            }

            Item { Layout.fillHeight: true }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                Layout.bottomMargin: 12

                Label {
                    text: "Changes take effect on next Steam launch."
                    opacity: 0.6
                }

                Item { Layout.fillWidth: true }

                Button {
                    text: "Save"
                    highlighted: true
                    onClicked: { if (backend) backend.saveConfig() }
                }
            }
        }
    }
}
