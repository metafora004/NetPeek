#include "MainWindow.h"

#include <QApplication>
#include <QColor>
#include <QPalette>
#include <QStyleFactory>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("NetPeek"));
    QApplication::setApplicationVersion(QStringLiteral("0.1.0"));
    QApplication::setOrganizationName(QStringLiteral("OneHackLab"));
    QApplication::setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette palette;
    palette.setColor(QPalette::Window, QColor(18, 24, 31));
    palette.setColor(QPalette::WindowText, QColor(225, 233, 240));
    palette.setColor(QPalette::Base, QColor(12, 17, 23));
    palette.setColor(QPalette::AlternateBase, QColor(22, 30, 39));
    palette.setColor(QPalette::Text, QColor(225, 233, 240));
    palette.setColor(QPalette::Button, QColor(28, 38, 49));
    palette.setColor(QPalette::ButtonText, QColor(225, 233, 240));
    palette.setColor(QPalette::Highlight, QColor(24, 184, 140));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    palette.setColor(QPalette::PlaceholderText, QColor(117, 133, 146));
    app.setPalette(palette);

    app.setStyleSheet(QStringLiteral(R"(
        QWidget { font-size: 10pt; }
        QMainWindow { background: #12181f; }
        QLineEdit, QSpinBox {
            border: 1px solid #344453; border-radius: 6px;
            padding: 7px 9px; background: #0c1117;
        }
        QPushButton {
            border: 1px solid #3a4b59; border-radius: 6px;
            padding: 7px 14px; background: #1c2631;
        }
        QPushButton:hover { border-color: #18b88c; }
        QPushButton:pressed { background: #142d2a; }
        QPushButton:disabled { color: #6e7b86; border-color: #2a353e; }
        QHeaderView::section {
            background: #1c2631; border: 0; border-bottom: 1px solid #344453;
            padding: 7px; font-weight: 600;
        }
        QTableWidget { border: 1px solid #293744; border-radius: 6px; gridline-color: #26333e; }
        QTabWidget::pane { border: 1px solid #293744; border-radius: 6px; }
        QTabBar::tab { padding: 9px 18px; }
        QTabBar::tab:selected { color: #22d3a4; border-bottom: 2px solid #22d3a4; }
        QProgressBar { border: 1px solid #344453; border-radius: 5px; text-align: center; }
        QProgressBar::chunk { background: #18b88c; border-radius: 4px; }
    )"));

    MainWindow window;
    window.show();
    return app.exec();
}
