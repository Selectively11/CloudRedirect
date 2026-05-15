import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "pages"

ApplicationWindow {
    id: root
    width: 720
    height: 620
    minimumWidth: 600
    minimumHeight: 500
    title: "CloudRedirect"
    visible: true

    // Navigate to Setup tab after deploy/undeploy actions if needed
    Connections {
        target: deployer
        function onCheckCompleted() {
            if (deployer && (!deployer.alreadyDeployed || deployer.updateAvailable)) {
                tabBar.currentIndex = 4  // Setup tab
            }
        }
    }

    // Auto-update prompt on first launch + initial setup navigation
    Component.onCompleted: {
        if (deployer && (!deployer.alreadyDeployed || deployer.updateAvailable)) {
            tabBar.currentIndex = 4
        }
        if (backend && backend.shouldOfferAutoUpdates()) {
            autoUpdateDialog.open()
        } else if (backend) {
            backend.checkForFlatpakUpdate()
        }
    }

    Connections {
        target: backend
        function onFlatpakUpdateAvailable() {
            updateAvailableDialog.open()
        }
        function onFlatpakUpdateCompleted(success) {
            if (success) {
                restartDialog.open()
            }
        }
    }

    Dialog {
        id: updateAvailableDialog
        title: "Update Available"
        modal: true
        standardButtons: Dialog.NoButton
        anchors.centerIn: parent
        width: Math.min(parent.width - 80, 440)

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "A new version of CloudRedirect is available."
                font.bold: true
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Label {
                text: "Update now to get the latest features and fixes."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                opacity: 0.7
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 4

                Item { Layout.fillWidth: true }

                Button {
                    text: "Later"
                    onClicked: updateAvailableDialog.close()
                }

                Button {
                    text: "Update Now"
                    highlighted: true
                    onClicked: {
                        if (backend) backend.applyFlatpakUpdate()
                        updateAvailableDialog.close()
                    }
                }
            }
        }
    }

    Dialog {
        id: restartDialog
        title: "Restart Required"
        modal: true
        standardButtons: Dialog.Ok
        anchors.centerIn: parent
        width: Math.min(parent.width - 80, 440)

        Label {
            text: "CloudRedirect has been updated. Please restart the application to use the new version."
            wrapMode: Text.WordWrap
            width: parent.width
        }
    }

    Dialog {
        id: autoUpdateDialog
        title: "Enable Automatic Updates"
        modal: true
        standardButtons: Dialog.NoButton
        anchors.centerIn: parent
        width: Math.min(parent.width - 80, 440)

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "Would you like to receive automatic updates?"
                font.bold: true
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Label {
                text: "CloudRedirect can add its update repository so new versions are installed automatically via Flatpak. You can remove it later from Settings."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                opacity: 0.7
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 4

                Item { Layout.fillWidth: true }

                Button {
                    text: "Not Now"
                    onClicked: {
                        if (backend) backend.dismissAutoUpdatePrompt()
                        autoUpdateDialog.close()
                    }
                }

                Button {
                    text: "Enable Updates"
                    highlighted: true
                    onClicked: {
                        if (backend) backend.enableAutoUpdates()
                        autoUpdateDialog.close()
                    }
                }
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        TabBar {
            id: tabBar
            Layout.fillWidth: true

            TabButton { text: "Dashboard" }
            TabButton { text: "Apps" }
            TabButton { text: "Backups" }
            TabButton { text: "Cloud Provider" }
            TabButton { text: "Setup" }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabBar.currentIndex

            DashboardPage {}
            AppsPage {}
            BackupsPage {}
            CloudProviderPage {}
            SetupPage {}
        }
    }
}
