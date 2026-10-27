#pragma once

#include "backend/preferences/preferences.h"
#include "backend/preferences/preferenceshelper.h"
#include "commongraphics/basepage.h"
#include "preferenceswindow/preferencegroup.h"
#include "splittunnelingaddressesgroup.h"
#include "splittunnelingcountriesgroup.h"

namespace PreferencesWindow {

class SplitTunnelingAddressesWindowItem : public CommonGraphics::BasePage
{
    Q_OBJECT
public:
    explicit SplitTunnelingAddressesWindowItem(ScalableGraphicsObject *parent, Preferences *preferences);

    QString caption() const override;
    void setFocusOnTextEntry();

    void setLoggedIn(bool loggedIn);

signals:
    void addressesUpdated(QList<types::SplitTunnelingNetworkRoute> addresses);
    void escape();

private slots:
    void onAddressesUpdated(QList<types::SplitTunnelingNetworkRoute> addresses);
    void onCountriesUpdated(QList<types::SplitTunnelingNetworkRoute> routes);
    void onGeoIpDatabasePathChanged(const QString &path);
    void onError(QString msg);
    void onClearError();
    void onLanguageChanged();
    void onPreferencesChanged();

private:
    Preferences *preferences_;
    PreferenceGroup *desc_;
    SplitTunnelingAddressesGroup *addressesGroup_;
    SplitTunnelingCountriesGroup *countriesGroup_;

    bool loggedIn_;
};

}
