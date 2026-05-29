cmake_minimum_required(VERSION 3.21)

project(mlsh-systray VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC OFF)

# QtNetwork is required for both the named-pipe IPC (QLocalSocket) and the
# GitHub update checker. No QML/Quick, no QtSvg — the tray icon is painted at
# runtime with QPainter.
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

qt_standard_project_setup()

set(SOURCES
    src/main.cpp
    src/App.cpp
    src/ipc/Protocol.cpp
    src/ipc/DaemonClient.cpp
    src/model/AppState.cpp
    src/config/ClusterDiscovery.cpp
    src/service/ServiceController.cpp
    src/update/UpdateChecker.cpp
    src/ui/IconFactory.cpp
    src/ui/Formatting.cpp
    src/ui/TunnelRow.cpp
    src/ui/MainWindow.cpp
    src/ui/TrayIcon.cpp
)

set(HEADERS
    src/App.h
    src/ipc/Protocol.h
    src/ipc/DaemonClient.h
    src/model/TunnelStatus.h
    src/model/AppState.h
    src/config/ClusterDiscovery.h
    src/service/ServiceController.h
    src/update/UpdateChecker.h
    src/ui/Theme.h
    src/ui/IconFactory.h
    src/ui/Formatting.h
    src/ui/TunnelRow.h
    src/ui/MainWindow.h
    src/ui/TrayIcon.h
)

# Embed the application icon on Windows (Explorer / taskbar / shortcuts).
if(WIN32)
    enable_language(RC)
    list(APPEND SOURCES resources/app.rc)
endif()

# WIN32 → GUI subsystem, no console window.
qt_add_executable(mlsh-systray WIN32 ${SOURCES} ${HEADERS})

target_include_directories(mlsh-systray PRIVATE src)

target_link_libraries(mlsh-systray PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

if(WIN32)
    # advapi32: Service Control Manager (status query).
    # shell32:  ShellExecuteEx (UAC elevation for service actions).
    target_link_libraries(mlsh-systray PRIVATE advapi32 shell32)
endif()

# Convenience: `cmake --build . --target deploy` runs windeployqt on the binary.
if(WIN32)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${Qt6_DIR}/../../../bin")
    if(WINDEPLOYQT_EXECUTABLE)
        add_custom_target(deploy
            COMMAND "${WINDEPLOYQT_EXECUTABLE}" --no-translations "$<TARGET_FILE:mlsh-systray>"
            DEPENDS mlsh-systray
            COMMENT "Running windeployqt on mlsh-systray.exe")
    endif()
endif()
