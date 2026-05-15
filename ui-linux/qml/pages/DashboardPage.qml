import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    title: "Dashboard"
    
    // Track auth state locally so bindings update
    property bool providerAuth: backend ? backend.providerAuthenticated : false

    function formatProviderName(name) {
        if (name === "gdrive") return "Google Drive"
        if (name === "onedrive") return "OneDrive"
        if (name === "local") return "Local"
        return name
    }
    
    function refreshState() {
        providerAuth = backend ? backend.providerAuthenticated : false
    }

    Component.onCompleted: {
        console.log("DashboardPage.onCompleted - calling fetchRemoteApps")
        // Fetch remote apps when dashboard loads
        if (backend) backend.fetchRemoteApps()
    }
    
    Connections {
        target: backend
        function onSettingsChanged() {
            refreshState()
        }
        function onStatusChanged() {
            refreshState()
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
                text: "Dashboard"
                font.pointSize: 16
                font.bold: true
                Layout.leftMargin: 20
            }

            Label {
                text: "CloudRedirect v" + (backend ? backend.version : "")
                Layout.leftMargin: 20
                opacity: 0.7
            }

            Label {
                text: "Welcome!"
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
                    anchors.fill: parent
                    spacing: 4

                    Label {
                        text: "Cloud Provider"
                        font.bold: true
                    }
                    Label {
                        text: {
                            if (!backend || !backend.providerName || backend.providerName === "local")
                                return "Not configured"
                            if (providerAuth)
                                return formatProviderName(backend.providerName) + " — Authenticated"
                            return formatProviderName(backend.providerName) + " — Not authenticated"
                        }
                        opacity: 0.7
                    }
                }
            }

            Frame {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 4

                    Label {
                        text: "Apps Syncing"
                        font.bold: true
                    }
                    Label {
                        text: {
                            var local = backend ? backend.managedAppCount : 0
                            var remoteOnly = backend ? backend.remoteOnlyAppCount : 0
                            if (remoteOnly > 0)
                                return local + " local, " + remoteOnly + " remote only"
                            return local + " app(s) with cloud data"
                        }
                        opacity: 0.7
                    }
                }
            }

            Frame {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 4

                    Label {
                        text: "CloudRedirect"
                        font.bold: true
                    }
                    Label {
                        text: (backend && backend.deployed) ? "Installed" : "Not installed"
                        opacity: 0.7
                    }
                }
            }

            RowLayout {
                Layout.leftMargin: 20
                spacing: 8

                Button {
                    text: "Open Log File"
                    onClicked: { if (backend) backend.openLogFile() }
                }

                Button {
                    text: "Open Config Folder"
                    onClicked: { if (backend) backend.openConfigFolder() }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
