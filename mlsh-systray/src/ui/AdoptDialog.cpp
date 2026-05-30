#include "ui/AdoptDialog.h"

#include "model/AppState.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

AdoptDialog::AdoptDialog(AppState *state, QWidget *parent)
    : QDialog(parent)
    , m_state(state)
{
    setWindowTitle(tr("Adopt a tunnel"));
    setModal(true);
    resize(460, 0);

    auto *outer = new QVBoxLayout(this);
    auto *form = new QFormLayout;

    m_url = new QLineEdit;
    m_url->setPlaceholderText(QStringLiteral("mlsh://signal.example.com:443/adopt/…"));
    form->addRow(tr("Adoption URL"), m_url);

    m_name = new QLineEdit;
    m_name->setPlaceholderText(tr("optional — defaults to hostname"));
    form->addRow(tr("Node name"), m_name);
    outer->addLayout(form);

    m_status = new QLabel;
    m_status->setWordWrap(true);
    outer->addWidget(m_status);

    m_buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    m_buttons->button(QDialogButtonBox::Ok)->setText(tr("Adopt"));
    outer->addWidget(m_buttons);

    connect(m_buttons, &QDialogButtonBox::accepted, this, &AdoptDialog::submit);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void AdoptDialog::submit()
{
    const QString url = m_url->text().trimmed();
    if (!url.startsWith(QStringLiteral("mlsh://")) && !url.startsWith(QStringLiteral("https://"))) {
        m_status->setText(tr("Enter a valid mlsh:// or https:// adoption URL."));
        return;
    }

    m_buttons->setEnabled(false);
    m_url->setEnabled(false);
    m_name->setEnabled(false);
    m_status->setText(tr("Joining cluster…"));

    m_state->adoptTunnel(url, m_name->text().trimmed(), [this](const CliRunner::Result &r) {
        if (r.ok) {
            accept();
        } else {
            m_buttons->setEnabled(true);
            m_url->setEnabled(true);
            m_name->setEnabled(true);
            m_status->setText(r.error.isEmpty() ? tr("Adoption failed.") : r.error);
        }
    });
}
