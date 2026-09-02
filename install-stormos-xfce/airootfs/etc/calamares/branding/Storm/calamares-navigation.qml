import io.calamares.ui 1.0
import io.calamares.core 1.0

import QtQuick 2.3
import QtQuick.Controls 2.10
import QtQuick.Layouts 1.3

Rectangle {
    id: navigationBar
    color: Branding.styleString( Branding.SidebarBackground )
    height: parent.height
    width: 64

    ColumnLayout {
        id: buttonBar
        anchors.fill: parent
        spacing: 1

        Image {
            id: logo
            Layout.topMargin: 1
            Layout.bottomMargin: parent.height / 7
            Layout.alignment: Qt.AlignHCenter | Qt.AlignTop
            width: 62
            height: width
            source: "file:/" + Branding.imagePath( Branding.ProductLogo )
            sourceSize.width: width
            sourceSize.height: height
        }

        Rectangle {
            id: backArea
            Layout.fillWidth: true
            Layout.preferredHeight: parent.height / 7
            color: mouseBack.containsMouse ? "#e6e9ea" : "#d9dcde"
            enabled: ViewManager.backEnabled
            visible: ViewManager.backAndNextVisible

            MouseArea {
                id: mouseBack
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true

                Text {
                    anchors.centerIn: parent
                    text: qsTr( "Back" )
                    color: Branding.styleString( !backArea.enabled ? Branding.SidebarBackground : (mouseBack.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                    font.pointSize: 8
                }
                Image {
                    source: "pan-start-symbolic.svg"
                    anchors.centerIn: parent
                    anchors.verticalCenterOffset: 18
                    fillMode: Image.PreserveAspectFit
                    height: 32
                    opacity: backArea.enabled ? 1 : 0.2
                }
                onClicked: ViewManager.back()
            }
        }

        Rectangle {
            id: nextArea
            Layout.fillWidth: true
            Layout.preferredHeight: parent.height / 7
            color: mouseNext.containsMouse ? "#f4f5f6" : "#e6e9ea"
            enabled: ViewManager.nextEnabled
            visible: ViewManager.backAndNextVisible

            MouseArea {
                id: mouseNext
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true

                Text {
                    anchors.centerIn: parent
                    text: qsTr( "Next" )
                    color: Branding.styleString( !nextArea.enabled ? Branding.SidebarBackground : (mouseNext.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                    font.pointSize: 8
                }
                Image {
                    source: "pan-end-symbolic.svg"
                    anchors.centerIn: parent
                    anchors.verticalCenterOffset: 18
                    fillMode: Image.PreserveAspectFit
                    height: 32
                    opacity: nextArea.enabled ? 1 : 0.2
                }
                onClicked: ViewManager.next()
            }
        }

        Rectangle {
            id: cancelArea
            Layout.fillWidth: true
            Layout.preferredHeight: parent.height / 7
            color: mouseCancel.containsMouse ? "#e6e9ea" : "#d9dcde"
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

                Text {
                    anchors.centerIn: parent
                    text: qsTr( "Cancel" )
                    color: Branding.styleString( !cancelArea.enabled ? Branding.SidebarBackground : (mouseCancel.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                    font.pointSize: 8
                }
                Image {
                    source: "draw-rectangle.svg"
                    anchors.centerIn: parent
                    anchors.verticalCenterOffset: 18
                    fillMode: Image.PreserveAspectFit
                    height: 9
                    opacity: cancelArea.enabled ? 1 : 0.2
                }
                onClicked: ViewManager.quit()
            }
        }

        Item {
            Layout.fillHeight: true
        }

        Rectangle {
            id: debugArea
            Layout.fillWidth: true
            height: 35
            Layout.alignment: Qt.AlignHCenter | Qt.AlignBottom
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
                    color: Branding.styleString( mouseAreaDebug.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarBackground )
                    font.pointSize: 8
                }
                onClicked: debug.toggle()
            }
        }

        Rectangle {
            id: aboutArea
            Layout.fillWidth: true
            height: 35
            Layout.alignment: Qt.AlignHCenter | Qt.AlignBottom
            color: Branding.styleString( mouseAreaAbout.containsMouse ? Branding.SidebarBackgroundCurrent : Branding.SidebarBackground )

            MouseArea {
                id: mouseAreaAbout
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true

                Text {
                    anchors.centerIn: parent
                    text: qsTr( "About" )
                    color: Branding.styleString( mouseAreaAbout.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarBackgroundCurrent )
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
}
