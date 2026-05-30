#include "ui/InviteDialog.h"

#include "model/AppState.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

InviteDialog::InviteDialog(AppState *state, const QString &cluster, QWidget *parent)
    : QDialog(parent)
    , m_state(state)
    , m_cluster(cluster)
{
    setWindowTitle(tr("Invite to %1").arg(cluster));
    setModal(true);
    resize(500, 0);

    auto *outer = new QVBoxLayout(this);
    auto *form = new QFormLayout;

    m_role = new QComboBox;
    m_role->addItems({QStringLiteral("node"), QStringLiteral("admin")});
    form->addRow(tr("Role"), m_role);

    m_ttl = new QSpinBox;
    m_ttl->setRange(60, 7 * 24 * 3600);
    m_ttl->setValue(3600);
    m_ttl->setSuffix(tr(" s"));
    m_ttl->setSingleStep(300);
    form->addRow(tr("Expires in"), m_ttl);
    outer->addLayout(form);

    m_generate = new QPushButton(tr("Generate invite"));
    outer->addWidget(m_generate);

    auto *urlRow = new QHBoxLayout;
    m_url = new QLineEdit;
    m_url->setReadOnly(true);
    m_url->setPlaceholderText(tr("the invite URL will appear here"));
    m_copy = new QPushButton(tr("Copy"));
    m_copy->setEnabled(false);
    urlRow->addWidget(m_url, 1);
    urlRow->addWidget(m_copy);
    outer->addLayout(urlRow);

    m_status = new QLabel;
    m_status->setWordWrap(true);
    m_status->setStyleSheet(QStringLiteral("color: palette(mid);"));
    outer->addWidget(m_status);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    outer->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_generate, &QPushButton::clicked, this, &InviteDialog::generate);
    connect(m_copy, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(m_url->text());
        m_status->setText(tr("Copied to clipboard."));
    });
}

void InviteDialog::generate()
{
    m_generate->setEnabled(false);
    m_status->setText(tr("Generating…"));

    m_state->inviteCluster(m_cluster, m_role->currentText(), m_ttl->value(),
                           [this](const CliRunner::Result &r) {
                               m_generate->setEnabled(true);
                               if (!r.ok) {
                                   m_status->setText(r.error.isEmpty() ? tr("Failed.") : r.error);
                                   return;
                               }
                               const QString url =
                                   r.data.toObject().value(QStringLiteral("url")).toString();
                               m_url->setText(url);
                               m_copy->setEnabled(!url.isEmpty());
                               m_status->setText(tr("Share this URL; run `mlsh adopt <url>` on the "
                                                    "other machine before it expires."));
                           });
}
