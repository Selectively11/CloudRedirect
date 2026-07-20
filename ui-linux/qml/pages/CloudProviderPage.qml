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
        { value: "onedrive", name: "OneDrive", desc: "Sync saves to your Microsoft OneDrive account." },
        { value: "r2", name: "Cloudflare R2", desc: "Sync saves to a Cloudflare R2 bucket (S3-compatible)." },
        { value: "s3", name: "S3 Compatible", desc: "Sync saves to any S3-compatible service (AWS S3, MinIO, Backblaze B2, Wasabi, self-hosted)." }
    ]

    property bool comboReady: false

    // True while a credential save + connection test is in flight (disables Save).
    property bool saving: false
    
    // Track auth state locally so bindings update when settingsChanged fires
    property bool gdriveAuth: backend ? backend.isProviderAuthenticated("gdrive") : false
    property bool onedriveAuth: backend ? backend.isProviderAuthenticated("onedrive") : false
    property bool r2Auth: backend ? backend.isProviderAuthenticated("r2") : false
    property bool s3Auth: backend ? backend.isProviderAuthenticated("s3") : false
    
    function refreshAuthState() {
        gdriveAuth = backend ? backend.isProviderAuthenticated("gdrive") : false
        onedriveAuth = backend ? backend.isProviderAuthenticated("onedrive") : false
        r2Auth = backend ? backend.isProviderAuthenticated("r2") : false
        s3Auth = backend ? backend.isProviderAuthenticated("s3") : false
    }

    // Pre-fill the R2 form from the saved credentials (non-secret fields only).
    function loadR2Form() {
        if (!backend) return
        var c = backend.getR2Credentials()
        r2AccountIdField.text = c.account_id || ""
        r2AccessKeyField.text = c.access_key_id || ""
        r2BucketField.text = c.bucket || ""
        r2KeyPrefixField.text = c.key_prefix || ""
        r2EndpointField.text = c.endpoint || ""
        // Leave the secret blank; show a hint that one is already stored.
        r2SecretField.text = ""
        r2HasSecret = c.has_secret === true
    }

    property bool r2HasSecret: false

    // Pre-fill the S3 form from the saved credentials (non-secret fields only).
    function loadS3Form() {
        if (!backend) return
        var c = backend.getS3Credentials()
        s3AccessKeyField.text = c.access_key_id || ""
        s3BucketField.text = c.bucket || ""
        s3EndpointField.text = c.endpoint || ""
        s3RegionField.text = c.region || ""
        s3KeyPrefixField.text = c.key_prefix || ""
        s3SignPayloadCheck.checked = c.sign_payload === true
        s3InsecureHttpCheck.checked = c.allow_insecure_http === true
        s3InsecureTlsCheck.checked = c.allow_insecure_tls === true
        s3CaCertField.text = c.ca_cert_path || ""
        // Leave the secret blank; show a hint that one is already stored.
        s3SecretField.text = ""
        s3HasSecret = c.has_secret === true
    }

    property bool s3HasSecret: false

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
        // Result of the on-save connection test for R2/S3.
        function onProviderTestFinished(provider, ok, error) {
            saving = false
            if (ok) {
                statusText.text = "Connected. Credentials saved."
                backend.saveConfig()
                refreshAuthState()
                if (provider === "s3") loadS3Form()
                else if (provider === "r2") loadR2Form()
            } else {
                statusText.text = "Error: " + error
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
                            if (provider.value === "r2") return r2Auth ? "Credentials saved" : "No credentials saved"
                            if (provider.value === "s3") return s3Auth ? "Credentials saved" : "No credentials saved"
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

            Frame {
                id: r2Frame
                visible: currentProvider().value === "r2"
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                // Populate the fields whenever this panel becomes visible.
                onVisibleChanged: if (visible) loadR2Form()

                ColumnLayout {
                    width: parent.width
                    spacing: 12

                    Label {
                        text: "Cloudflare R2 Credentials"
                        font.bold: true
                    }
                    Label {
                        text: "Create an R2 bucket on your Cloudflare Dashboard. Generate tokens, enter them here. "
                            + "Credentials entered here are stored in r2_credentials.json"
                        opacity: 0.6
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Account ID"; opacity: 0.8 }
                        TextField {
                            id: r2AccountIdField
                            Layout.fillWidth: true
                            placeholderText: "e.g. 1a2b3c4d5e6f..."
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Access Key ID"; opacity: 0.8 }
                        TextField {
                            id: r2AccessKeyField
                            Layout.fillWidth: true
                            placeholderText: "R2 access key id"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Secret Access Key"; opacity: 0.8 }
                        TextField {
                            id: r2SecretField
                            Layout.fillWidth: true
                            echoMode: TextInput.Password
                            placeholderText: r2HasSecret
                                ? "(unchanged - leave blank to keep existing)"
                                : "R2 secret access key"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Bucket"; opacity: 0.8 }
                        TextField {
                            id: r2BucketField
                            Layout.fillWidth: true
                            placeholderText: "bucket name"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Key Prefix (optional)"; opacity: 0.8 }
                        TextField {
                            id: r2KeyPrefixField
                            Layout.fillWidth: true
                            placeholderText: "e.g. cloudredirect/"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Endpoint (optional)"; opacity: 0.8 }
                        TextField {
                            id: r2EndpointField
                            Layout.fillWidth: true
                            placeholderText: "leave blank for <account>.r2.cloudflarestorage.com"
                        }
                    }

                }
            }

            Frame {
                id: s3Frame
                visible: currentProvider().value === "s3"
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20

                // Populate the fields whenever this panel becomes visible.
                onVisibleChanged: if (visible) loadS3Form()

                ColumnLayout {
                    width: parent.width
                    spacing: 12

                    Label {
                        text: "S3 Compatible Credentials"
                        font.bold: true
                    }
                    Label {
                        text: "Add your S3 compatible provider"
                        opacity: 0.6
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Endpoint"; opacity: 0.8 }
                        TextField {
                            id: s3EndpointField
                            Layout.fillWidth: true
                            placeholderText: "e.g. s3.us-east-1.amazonaws.com or minio.example.com:9000"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Access Key ID"; opacity: 0.8 }
                        TextField {
                            id: s3AccessKeyField
                            Layout.fillWidth: true
                            placeholderText: "access key id"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Secret Access Key"; opacity: 0.8 }
                        TextField {
                            id: s3SecretField
                            Layout.fillWidth: true
                            echoMode: TextInput.Password
                            placeholderText: s3HasSecret
                                ? "(unchanged - leave blank to keep existing)"
                                : "secret access key"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Bucket"; opacity: 0.8 }
                        TextField {
                            id: s3BucketField
                            Layout.fillWidth: true
                            placeholderText: "bucket name"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Region"; opacity: 0.8 }
                        TextField {
                            id: s3RegionField
                            Layout.fillWidth: true
                            placeholderText: "e.g. us-east-1"
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "Key Prefix (optional)"; opacity: 0.8 }
                        TextField {
                            id: s3KeyPrefixField
                            Layout.fillWidth: true
                            placeholderText: "e.g. cloudredirect/"
                        }
                    }

                    // ── Advanced: transport + signing options for self-hosted servers ──
                    Label {
                        text: "Advanced"
                        font.bold: true
                        Layout.topMargin: 4
                    }

                    CheckBox {
                        id: s3SignPayloadCheck
                        text: "Sign request payloads (SHA-256 body hash)"
                    }
                    CheckBox {
                        id: s3InsecureHttpCheck
                        text: "Allow plain HTTP endpoints (insecure)"
                    }
                    CheckBox {
                        id: s3InsecureTlsCheck
                        text: "Skip TLS certificate verification (insecure)"
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Label { text: "CA Certificate Path (optional)"; opacity: 0.8 }
                        TextField {
                            id: s3CaCertField
                            Layout.fillWidth: true
                            placeholderText: "e.g. /path/to/ca.pem for a self-signed server"
                        }
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
                    text: saving ? "Testing connection..." : "Save"
                    highlighted: true
                    enabled: !saving
                    onClicked: {
                        if (!backend) return
                        var p = currentProvider().value

                        if (p === "s3") {
                            var okS3 = backend.saveS3Credentials(
                                s3AccessKeyField.text,
                                s3SecretField.text,
                                s3BucketField.text,
                                s3EndpointField.text,
                                s3RegionField.text,
                                s3KeyPrefixField.text,
                                s3SignPayloadCheck.checked,
                                s3InsecureHttpCheck.checked,
                                s3InsecureTlsCheck.checked,
                                s3CaCertField.text)
                            if (!okS3) {
                                statusText.text = "Error: Access Key ID, Secret Access Key, "
                                    + "Bucket, Endpoint and Region are required."
                                return
                            }
                            // Verify the endpoint actually works before committing.
                            statusText.text = "Testing connection..."
                            saving = true
                            backend.testProviderConnection("s3")
                            return
                        }

                        if (p === "r2") {
                            var okR2 = backend.saveR2Credentials(
                                r2AccountIdField.text,
                                r2AccessKeyField.text,
                                r2SecretField.text,
                                r2BucketField.text,
                                r2KeyPrefixField.text,
                                r2EndpointField.text)
                            if (!okR2) {
                                statusText.text = "Error: Account ID, Access Key ID, "
                                    + "Bucket and Secret Access Key are required."
                                return
                            }
                            statusText.text = "Testing connection..."
                            saving = true
                            backend.testProviderConnection("r2")
                            return
                        }

                        // Non-credential providers just persist config.
                        backend.saveConfig()
                        statusText.text = "Saved."
                    }
                }
            }
        }
    }
}
