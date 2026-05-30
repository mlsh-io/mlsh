#pragma once

#include <QDialog>

class AppState;
class QLineEdit;
class QLabel;
class QDialogButtonBox;

/// Join an existing cluster from an adoption URL (`mlsh --json adopt <url>`).
class AdoptDialog : public QDialog
{
    Q_OBJECT
public:
    explicit AdoptDialog(AppState *state, QWidget *parent = nullptr);

private:
    void submit();

    AppState *m_state = nullptr;
    QLineEdit *m_url = nullptr;
    QLineEdit *m_name = nullptr;
    QLabel *m_status = nullptr;
    QDialogButtonBox *m_buttons = nullptr;
};
