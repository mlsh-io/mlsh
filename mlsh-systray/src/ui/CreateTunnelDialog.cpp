#include "ui/CreateTunnelDialog.h"

#include "cli/CliRunner.h"
#include "model/AppState.h"

#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QTabWidget>
#include <QUrl>
#include <QVBoxLayout>

CreateTunnelDialog::CreateTunnelDialog(AppState *state, QWidget *parent)
    : QDialog(parent)
    , m_state(state)
{
    setWindowTitle(tr("New tunnel"));
    setModal(true);
    resize(540, 420);

    auto *outer = new QVBoxLayout(this);
    auto *tabs = new QTabWidget;
    tabs->addTab(buildManagedTab(), tr("Managed (mlsh.io)"));
    tabs->addTab(buildSelfHostedTab(), tr("Self-hosted"));
    outer->addWidget(tabs, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    outer->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

QWidget *CreateTunnelDialog::buildManagedTab()
{
    auto *w = new QWidget;
    auto *v = new QVBoxLayout(w);
    auto *form = new QFormLayout;

    m_mgCluster = new QLineEdit;
    m_mgCluster->setPlaceholderText(tr("cluster name"));
    form->addRow(tr("Cluster"), m_mgCluster);
    m_mgName = new QLineEdit;
    m_mgName->setPlaceholderText(tr("optional — defaults to hostname"));
    form->addRow(tr("Node name"), m_mgName);
    v->addLayout(form);

    m_mgCreate = new QPushButton(tr("Create & authorize"));
    v->addWidget(m_mgCreate);

    m_mgCode = new QLabel;
    m_mgCode->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(m_mgCode);

    m_mgVisit = new QPushButton(tr("Open authorization page"));
    m_mgVisit->setVisible(false);
    v->addWidget(m_mgVisit);

    m_mgLog = new QPlainTextEdit;
    m_mgLog->setReadOnly(true);
    v->addWidget(m_mgLog, 1);

    connect(m_mgCreate, &QPushButton::clicked, this, &CreateTunnelDialog::startManaged);
    connect(m_mgVisit, &QPushButton::clicked, this, [this]() {
        if (!m_visitUrl.isEmpty())
            QDesktopServices::openUrl(QUrl(m_visitUrl));
    });
    return w;
}

QWidget *CreateTunnelDialog::buildSelfHostedTab()
{
    auto *w = new QWidget;
    auto *v = new QVBoxLayout(w);
    auto *form = new QFormLayout;

    m_shCluster = new QLineEdit;
    m_shCluster->setPlaceholderText(tr("cluster name"));
    form->addRow(tr("Cluster"), m_shCluster);
    m_shHost = new QLineEdit;
    m_shHost->setPlaceholderText(tr("signal.example.com:4433"));
    form->addRow(tr("Signal host"), m_shHost);
    m_shToken = new QLineEdit;
    m_shToken->setPlaceholderText(tr("CODE@UUID@FINGERPRINT"));
    form->addRow(tr("Token"), m_shToken);
    m_shName = new QLineEdit;
    m_shName->setPlaceholderText(tr("optional — defaults to hostname"));
    form->addRow(tr("Node name"), m_shName);
    v->addLayout(form);

    m_shCreate = new QPushButton(tr("Create"));
    v->addWidget(m_shCreate);
    m_shStatus = new QLabel;
    m_shStatus->setWordWrap(true);
    m_shStatus->setStyleSheet(QStringLiteral("color: palette(mid);"));
    v->addWidget(m_shStatus);
    v->addStretch();

    connect(m_shCreate, &QPushButton::clicked, this, &CreateTunnelDialog::startSelfHosted);
    return w;
}

void CreateTunnelDialog::startManaged()
{
    const QString cluster = m_mgCluster->text().trimmed();
    if (cluster.isEmpty()) {
        m_mgLog->appendPlainText(tr("Enter a cluster name."));
        return;
    }
    m_mgCreate->setEnabled(false);
    m_mgCluster->setEnabled(false);
    m_mgName->setEnabled(false);
    m_mgLog->clear();
    m_mgCode->clear();
    m_mgVisit->setVisible(false);
    m_visitUrl.clear();

    QStringList args{QStringLiteral("setup"), cluster};
    const QString name = m_mgName->text().trimmed();
    if (!name.isEmpty())
        args << QStringLiteral("--name") << name;

    m_runner = new CliRunner(this);
    connect(m_runner, &CliRunner::outputLine, this, &CreateTunnelDialog::onManagedLine);
    connect(m_runner, &CliRunner::streamFinished, this, &CreateTunnelDialog::onManagedFinished);
    m_runner->runStreaming(args); // human mode (device flow not available with --json)
}

void CreateTunnelDialog::onManagedLine(const QString &rawLine)
{
    // Strip any ANSI color codes just in case.
    static const QRegularExpression ansi(QStringLiteral("\\x1B\\[[0-9;]*m"));
    QString line = rawLine;
    line.remove(ansi);
    m_mgLog->appendPlainText(line);

    // Managed device flow prints "  Open: <url>" and "  Code: <code>".
    static const QRegularExpression visitRe(QStringLiteral("(?:Open|Visit):\\s*(\\S+)"));
    static const QRegularExpression codeRe(QStringLiteral("Code:\\s*(\\S+)"));
    QRegularExpressionMatch m = visitRe.match(line);
    if (m.hasMatch()) {
        m_visitUrl = m.captured(1);
        m_mgVisit->setVisible(true);
    }
    m = codeRe.match(line);
    if (m.hasMatch())
        m_mgCode->setText(tr("Enter this code in the browser: %1").arg(m.captured(1)));
}

void CreateTunnelDialog::onManagedFinished(int exitCode)
{
    if (m_runner) {
        m_runner->deleteLater();
        m_runner = nullptr;
    }
    if (exitCode == 0) {
        m_state->refreshNow();
        accept();
        return;
    }
    m_mgLog->appendPlainText(tr("\nSetup failed (exit %1).").arg(exitCode));
    m_mgCreate->setEnabled(true);
    m_mgCluster->setEnabled(true);
    m_mgName->setEnabled(true);
}

void CreateTunnelDialog::startSelfHosted()
{
    const QString cluster = m_shCluster->text().trimmed();
    const QString host = m_shHost->text().trimmed();
    const QString token = m_shToken->text().trimmed();
    if (cluster.isEmpty() || host.isEmpty() || token.isEmpty()) {
        m_shStatus->setText(tr("Cluster, signal host and token are required."));
        return;
    }
    m_shCreate->setEnabled(false);
    m_shStatus->setText(tr("Creating…"));
    m_state->createSelfHosted(cluster, host, token, m_shName->text().trimmed(),
                              [this](const CliRunner::Result &r) {
                                  if (r.ok) {
                                      accept();
                                  } else {
                                      m_shCreate->setEnabled(true);
                                      m_shStatus->setText(r.error.isEmpty() ? tr("Setup failed.")
                                                                            : r.error);
                                  }
                              });
}

void CreateTunnelDialog::reject()
{
    if (m_runner) {
        m_runner->cancel();
        m_runner->deleteLater();
        m_runner = nullptr;
    }
    QDialog::reject();
}
