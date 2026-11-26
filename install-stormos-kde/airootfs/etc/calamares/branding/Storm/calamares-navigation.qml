import io.calamares.ui 1.0
import io.calamares.core 1.0

import QtQuick 2.3
import QtQuick.Controls 2.10
import QtQuick.Layouts 1.3

Rectangle {
    id: navigationBar
    anchors.bottom: parent.bottom
    anchors.left: parent.left
    anchors.right: parent.right
    height: 48
    color: Branding.styleString( Branding.SidebarBackground )

    property bool __backHover: false
    property bool __nextHover: false
    property bool __cancelHover: false

    RowLayout {
        anchors.fill: parent
        anchors.margins: 4
        spacing: 8

        // Back button
        Rectangle {
            id: backArea
            width: 80
            height: 36
            radius: 4
            color: __backHover ? Branding.styleString( Branding.SidebarBackgroundCurrent ) : Branding.styleString( Branding.SidebarBackground )
            enabled: ViewManager.backEnabled
            visible: ViewManager.backAndNextVisible

            Image {
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: 10
                source: "pan-start-symbolic.svg"
                fillMode: Image.PreserveAspectFit
                height: 14
                opacity: backArea.enabled ? 1 : 0.3
            }

            Text {
                anchors.right: parent.right
                anchors.rightMargin: 10
                anchors.verticalCenter: parent.verticalCenter
                text: qsTr( "Back" )
                color: Branding.styleString( !backArea.enabled ? Branding.SidebarBackground : (__backHover ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                font.pointSize: 9
                font.bold: true
            }

            MouseArea {
                id: mouseBack
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onEntered: parent.__backHover = true
                onExited: parent.__backHover = false
                onClicked: ViewManager.back()
            }
        }

        // Next button (fills remaining space)
        Rectangle {
            id: nextArea
            Layout.fillWidth: true
            height: 36
            radius: 4
            color: __nextHover ? Branding.styleString( Branding.SidebarBackgroundCurrent ) : Branding.styleString( Branding.SidebarBackground )
            enabled: ViewManager.nextEnabled
            visible: ViewManager.backAndNextVisible

            Image {
                anchors.right: parent.right
                anchors.rightMargin: 10
                anchors.verticalCenter: parent.verticalCenter
                source: "pan-end-symbolic.svg"
                fillMode: Image.PreserveAspectFit
                height: 14
                opacity: nextArea.enabled ? 1 : 0.3
            }

            Text {
                anchors.left: parent.left
                anchors.leftMargin: 10
                anchors.right: parent.right
                anchors.rightMargin: 30
                anchors.verticalCenter: parent.verticalCenter
                text: qsTr( "Next" )
                color: Branding.styleString( !nextArea.enabled ? Branding.SidebarBackground : (__nextHover ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                font.pointSize: 9
                font.bold: true
            }

            MouseArea {
                id: mouseNext
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onEntered: parent.__nextHover = true
                onExited: parent.__nextHover = false
                onClicked: ViewManager.next()
            }
        }

        // Cancel button
        Rectangle {
            id: cancelArea
            width: 80
            height: 36
            radius: 4
            color: __cancelHover ? Branding.styleString( Branding.SidebarBackgroundCurrent ) : Branding.styleString( Branding.SidebarBackground )
            enabled: ViewManager.quitEnabled
            visible: ViewManager.quitVisible && (ViewManager.currentStepIndex < ViewManager.rowCount() - 1)

            ToolTip {
                visible: __cancelHover
                timeout: 5000
                delay: 1000
                text: ViewManager.quitTooltip
            }

            Image {
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: 10
                source: "draw-rectangle.svg"
                fillMode: Image.PreserveAspectFit
                height: 11
                opacity: cancelArea.enabled ? 1 : 0.3
            }

            Text {
                anchors.right: parent.right
                anchors.rightMargin: 10
                anchors.verticalCenter: parent.verticalCenter
                text: qsTr( "Cancel" )
                color: Branding.styleString( !cancelArea.enabled ? Branding.SidebarBackground : (__cancelHover ? Branding.SidebarTextCurrent : Branding.SidebarText) )
                font.pointSize: 9
            }

            MouseArea {
                id: mouseCancel
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onEntered: parent.__cancelHover = true
                onExited: parent.__cancelHover = false
                onClicked: ViewManager.quit()
            }
        }
    }

    // Install progress bar (thin line above buttons)
    Rectangle {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: 3
        radius: 1.5
        color: Branding.styleString( Branding.SidebarBackground )
        visible: ViewManager.jobQueue && ViewManager.jobQueue.length > 0
    }

    // Debug and About buttons at bottom-right, above progress bar
    Rectangle {
        id: debugArea
        anchors.bottom: progressBar.top
        anchors.right: parent.right
        anchors.margins: 2
        width: 72
        height: 22
        radius: 3
        color: Branding.styleString( mouseAreaDebug.containsMouse ? Branding.SidebarBackgroundCurrent : Branding.SidebarBackground )
        visible: debug.enabled

        Text {
            anchors.centerIn: parent
            text: qsTr( "Debug" )
            color: Branding.styleString( mouseAreaDebug.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText )
            font.pointSize: 7
        }

        MouseArea {
            id: mouseAreaDebug
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            hoverEnabled: true
            onClicked: debug.toggle()
        }
    }

    Rectangle {
        id: aboutArea
        anchors.bottom: progressBar.top
        anchors.right: debugArea.left
        anchors.margins: 2
        width: 64
        height: 22
        radius: 3
        color: Branding.styleString( mouseAreaAbout.containsMouse ? Branding.SidebarBackgroundCurrent : Branding.SidebarBackground )

        Text {
            anchors.centerIn: parent
            text: qsTr( "About" )
            color: Branding.styleString( mouseAreaAbout.containsMouse ? Branding.SidebarTextCurrent : Branding.SidebarText )
            font.pointSize: 7

            ToolTip {
                visible: mouseAreaAbout.containsMouse
                delay: 1000
                text: qsTr( "Info about Calamares" )
            }
        }

        MouseArea {
            id: mouseAreaAbout
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            hoverEnabled: true
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
