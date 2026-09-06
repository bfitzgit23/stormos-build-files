import io.calamares.ui 1.0
import io.calamares.core 1.0

import QtQuick 2.3
import QtQuick.Controls 2.10
import QtQuick.Layouts 1.3

Item {
    id: navigationBar
    anchors.fill: parent

    // Bottom button bar
    Rectangle {
        id: buttonBar
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: 56
        color: Branding.styleString( Branding.SidebarBackground )

        RowLayout {
            anchors.fill: parent
            anchors.margins: 8
            spacing: 12

            // Back button
            Rectangle {
                id: backArea
                Layout.preferredWidth: 90
                Layout.preferredHeight: 0
                height: 32
                radius: 4
                color: mouseBack.containsMouse ? Branding.styleString( Branding.SidebarBackgroundCurrent ) : Branding.styleString( Branding.SidebarBackground )
                enabled: ViewManager.backEnabled
                visible: ViewManager.backAndNextVisible

                MouseArea {
                    id: mouseBack
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 0
                        spacing: 0
                        implicitHeight: parent.height

                        Image {
                            source: "pan-start-symbolic.svg"
                            Layout.alignment: Qt.AlignHCenter
                            fillMode: Image.PreserveAspectFit
                            height: 14
                            opacity: backArea.enabled ? 1 : 0.3
                        }

                        Text {
                            text: qsTr( "Back" )
                            Layout.alignment: Qt.AlignHCenter
                            color: Branding.styleString( !backArea.enabled ? Branding.SidebarBackground : (mouseBack.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                            font.pointSize: 9
                            font.bold: true
                        }
                    }

                    onClicked: ViewManager.back()
                }
            }

            // Next button (wider — primary action)
            Rectangle {
                id: nextArea
                Layout.fillWidth: true
                Layout.preferredHeight: 0
                height: 32
                radius: 4
                color: mouseNext.containsMouse ? Branding.styleString( Branding.SidebarBackgroundCurrent ) : Branding.styleString( Branding.SidebarBackground )
                enabled: ViewManager.nextEnabled
                visible: ViewManager.backAndNextVisible

                MouseArea {
                    id: mouseNext
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 0
                        spacing: 0
                        implicitHeight: parent.height

                        Text {
                            text: qsTr( "Next" )
                            Layout.alignment: Qt.AlignHCenter
                            color: Branding.styleString( !nextArea.enabled ? Branding.SidebarBackground : (mouseNext.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                            font.pointSize: 9
                            font.bold: true
                        }

                        Image {
                            source: "pan-end-symbolic.svg"
                            Layout.alignment: Qt.AlignHCenter
                            fillMode: Image.PreserveAspectFit
                            height: 14
                            opacity: nextArea.enabled ? 1 : 0.3
                        }
                    }

                    onClicked: ViewManager.next()
                }
            }

            // Cancel button
            Rectangle {
                id: cancelArea
                Layout.preferredWidth: 90
                Layout.preferredHeight: 0
                height: 32
                radius: 4
                color: mouseCancel.containsMouse ? Branding.styleString( Branding.SidebarBackgroundCurrent ) : Branding.styleString( Branding.SidebarBackground )
                enabled: ViewManager.quitEnabled
                visible: ViewManager.quitVisible && (ViewManager.currentStepIndex < ViewManager.rowCount() - 1)

                ToolTip {
                    visible: mouseCancel.containsMouse
                    timeout: 5000
                    delay: 1000
                    text: ViewManager.quitTooltip
                }

                MouseArea {
                    id: mouseCancel
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 0
                        spacing: 0
                        implicitHeight: parent.height

                        Image {
                            source: "draw-rectangle.svg"
                            Layout.alignment: Qt.AlignHCenter
                            fillMode: Image.PreserveAspectFit
                            height: 11
                            opacity: cancelArea.enabled ? 1 : 0.3
                        }

                        Text {
                            text: qsTr( "Cancel" )
                            Layout.alignment: Qt.AlignHCenter
                            color: Branding.styleString( !cancelArea.enabled ? Branding.SidebarBackground : (mouseCancel.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                            font.pointSize: 9
                        }
                    }

                    onClicked: ViewManager.quit()
                }
            }
        }

        // Install progress bar (thin line above buttons)
        Rectangle {
            id: progressBar
            Layout.fillWidth: true
            height: 3
            radius: 1.5
            color: Branding.styleString( Branding.SidebarBackground )
            visible: ViewManager.jobQueue && ViewManager.jobQueue.length > 0
        }
    }

    // Debug and About buttons at bottom-right corner
    Rectangle {
        id: debugArea
        anchors.bottom: buttonBar.top
        anchors.right: parent.right
        anchors.margins: 4
        width: 80
        height: 28
        radius: 4
        color: Branding.styleString( mouseAreaDebug.containsMouse ? Branding.SidebarBackgroundCurrent : Branding.SidebarBackground )
        visible: debug.enabled

        MouseArea {
            id: mouseAreaDebug
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            hoverEnabled: true

            Text {
                anchors.centerIn: parent
                text: qsTr( "Debug" )
                color: Branding.styleString( mouseAreaDebug.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText )
                font.pointSize: 8
            }

            onClicked: debug.toggle()
        }
    }

    Rectangle {
        id: aboutArea
        anchors.bottom: buttonBar.top
        anchors.right: debugArea.left
        anchors.margins: 4
        width: 80
        height: 28
        radius: 4
        color: Branding.styleString( mouseAreaAbout.containsMouse ? Branding.SidebarBackgroundCurrent : Branding.SidebarBackground )

        MouseArea {
            id: mouseAreaAbout
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            hoverEnabled: true

            Text {
                anchors.centerIn: parent
                text: qsTr( "About" )
                color: Branding.styleString( mouseAreaAbout.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText )
                font.pointSize: 8

                ToolTip {
                    visible: mouseAreaAbout.containsMouse
                    delay: 1000
                    text: qsTr( "Info about Calamares" )
                }
            }

            property var window
            onClicked: {
                var component = Qt.createComponent( "about.qml" )
                window = component.createObject()
                if (window) {
                    window.show()
                }
            }
        }
    }
}
