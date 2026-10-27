#pragma once

#include <QHash>
#include "preferenceswindow/preferencegroup.h"
#include "preferenceswindow/comboboxitem.h"
#include "preferenceswindow/editboxitem.h"
#include "splittunnelingwindow/addressitem.h"

namespace PreferencesWindow {

// Country pass-through UI for split tunneling: the GeoIP database file selector (bring-your-own
// database, see docs/plans/split-tunneling-regex-and-country.md) plus a country picker whose
// selections become SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY entries in the shared routes list.
// Entries of other kinds are carried through untouched (this group is not their editor).
class SplitTunnelingCountriesGroup : public PreferenceGroup
{
    Q_OBJECT
public:
    explicit SplitTunnelingCountriesGroup(ScalableGraphicsObject *parent = nullptr);

    // Receives the FULL routes list; displays only the COUNTRY entries, preserves the rest.
    void setRoutes(const QList<types::SplitTunnelingNetworkRoute> &routes);
    void setGeoIpDatabasePath(const QString &path);
    void setLoggedIn(bool loggedIn);

signals:
    void routesUpdated(const QList<types::SplitTunnelingNetworkRoute> &routes);
    void geoIpDatabasePathChanged(const QString &path);
    void escape();
    void setError(const QString &msg);
    void clearError();

private slots:
void onPathEdited(const QString &text);
    void onPickerActivated(QVariant value);
    void onDeleteClicked();

private:
    void addCountryInternal(const types::SplitTunnelingNetworkRoute &route);
    void updateDbStatus();
    QList<types::SplitTunnelingNetworkRoute> currentFullList() const;
    QString countryCodeToDisplayName(const QString &code) const;

    EditBoxItem *dbPathItem_;
    ComboBoxItem *picker_;
    QHash<AddressItem *, types::SplitTunnelingNetworkRoute> items_;
    QList<types::SplitTunnelingNetworkRoute> passthrough_;   // non-country entries, preserved verbatim
    QList<types::SplitTunnelingNetworkRoute> lastRoutes_;    // re-entrancy guard for preference round-trips
    QString dbPath_;
    bool loggedIn_ = false;
};

} // namespace PreferencesWindow
