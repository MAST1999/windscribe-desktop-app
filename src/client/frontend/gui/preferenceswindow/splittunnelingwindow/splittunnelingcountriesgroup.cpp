#include "splittunnelingcountriesgroup.h"

#include <QFile>
#include <QLocale>
#include <utility>
#include "utils/networkingvalidation.h"

namespace PreferencesWindow {

SplitTunnelingCountriesGroup::SplitTunnelingCountriesGroup(ScalableGraphicsObject *parent)
  : PreferenceGroup(parent)
{
    setFlags(flags() | QGraphicsItem::ItemIsFocusable);

    dbPathItem_ = new EditBoxItem(this, tr("GeoIP database file (CSV)"), tr("Path to dbip-country-lite.csv or GeoLite2-Country-Blocks-IPv4.csv"));
    connect(dbPathItem_, &EditBoxItem::textChanged, this, &SplitTunnelingCountriesGroup::onPathEdited);
    addItem(dbPathItem_);

    picker_ = new ComboBoxItem(this, tr("Add country"));
    connect(picker_, &ComboBoxItem::currentItemChanged, this, &SplitTunnelingCountriesGroup::onPickerActivated);
    addItem(picker_);

    // Populated in updateScaling-independent form: display name + lowercase ISO code payload.
    QList<QPair<QString, QVariant>> countries;
    const auto locales = QLocale::matchingLocales(QLocale::AnyLanguage, QLocale::AnyScript, QLocale::AnyTerritory);
    QSet<QString> seen;
    for (const QLocale &loc : locales) {
        const QString code = QLocale::territoryToCode(loc.territory());
        if (code.size() != 2 || seen.contains(code)) {
            continue;
        }
        seen.insert(code);
        countries << qMakePair(code + " — " + QLocale::territoryToString(loc.territory()), QVariant(code.toLower()));
    }
    std::sort(countries.begin(), countries.end(), [](const QPair<QString, QVariant> &a, const QPair<QString, QVariant> &b) {
        return a.first < b.first;
    });
    picker_->setItems(countries, QVariant());
}

void SplitTunnelingCountriesGroup::setRoutes(const QList<types::SplitTunnelingNetworkRoute> &routes)
{
    // Re-entrancy guard: our own write-backs round-trip through Preferences::splitTunnelingChanged.
    if (routes == lastRoutes_) {
        return;
    }
    lastRoutes_ = routes;

    for (AddressItem *item : items_.keys()) {
        items_.remove(item);
        hideItems(indexOf(item), -1, DISPLAY_FLAGS::FLAG_DELETE_AFTER);
    }

    passthrough_.clear();
    for (const types::SplitTunnelingNetworkRoute &route : routes) {
        if (route.type == SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY) {
            addCountryInternal(route);
        } else {
            passthrough_ << route;
        }
    }
}

void SplitTunnelingCountriesGroup::setGeoIpDatabasePath(const QString &path)
{
    if (dbPath_ == path) {
        return;
    }
    dbPath_ = path;
    dbPathItem_->setText(path);
    updateDbStatus();
}

void SplitTunnelingCountriesGroup::setLoggedIn(bool loggedIn)
{
    loggedIn_ = loggedIn;
    dbPathItem_->setClickable(loggedIn);
    picker_->setClickable(loggedIn);
    for (AddressItem *item : items_.keys()) {
        item->setClickable(loggedIn);
    }
}

void SplitTunnelingCountriesGroup::setIncludeMode(bool includeMode)
{
    if (includeMode_ == includeMode) {
        return;
    }
    includeMode_ = includeMode;
    updateDbStatus();
}

void SplitTunnelingCountriesGroup::onPathEdited(const QString &text)
{
    dbPath_ = text.trimmed();
    updateDbStatus();
    emit geoIpDatabasePathChanged(dbPath_);
}

void SplitTunnelingCountriesGroup::onPickerActivated(QVariant value)
{
    if (!value.isValid()) {
        return;
    }
    const QString code = value.toString();

    for (const types::SplitTunnelingNetworkRoute &r : std::as_const(items_)) {
        if (r.name == code) {
            emit setError(tr("That country is already in the list."));
            return;
        }
    }
    if (!loggedIn_) {
        emit setError(tr("Please log in to modify split tunneling rules."));
        return;
    }

    types::SplitTunnelingNetworkRoute route;
    route.type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY;
    route.name = code;
    route.active = true;
    addCountryInternal(route);
    emit routesUpdated(currentFullList());
    emit clearError();
}

void SplitTunnelingCountriesGroup::addCountryInternal(const types::SplitTunnelingNetworkRoute &route)
{
    AddressItem *item = new AddressItem(route, this);
    connect(item, &AddressItem::deleteClicked, this, &SplitTunnelingCountriesGroup::onDeleteClicked);
    connect(item, &AddressItem::activeChanged, this, [this, item](bool active) {
        items_[item].active = active;
        emit routesUpdated(currentFullList());
    });
    items_[item] = route;
    addItem(item);
    hideItems(indexOf(item), -1, DISPLAY_FLAGS::FLAG_NO_ANIMATION);
    showItems(indexOf(item));
}

void SplitTunnelingCountriesGroup::onDeleteClicked()
{
    AddressItem *item = static_cast<AddressItem *>(sender());
    items_.remove(item);
    hideItems(indexOf(item), -1, DISPLAY_FLAGS::FLAG_DELETE_AFTER);
    emit routesUpdated(currentFullList());
}

QList<types::SplitTunnelingNetworkRoute> SplitTunnelingCountriesGroup::currentFullList() const
{
    QList<types::SplitTunnelingNetworkRoute> out = passthrough_;
    for (const types::SplitTunnelingNetworkRoute &r : items_) {
        out << r;
    }
    return out;
}

void SplitTunnelingCountriesGroup::updateDbStatus()
{
    if (includeMode_) {
        // Country pass-through is exclude-mode-only: in include mode everything outside the
        // tunnel already egresses directly, so the selection would be a no-op (spec §5.5).
        picker_->setClickable(false);
        dbPathItem_->setPrompt(tr("Country rules apply in Exclude mode only"));
        return;
    }
    if (dbPath_.isEmpty()) {
        picker_->setClickable(false);
        dbPathItem_->setPrompt(tr("No database selected — download DB-IP LITE (db-ip.com/db/lite.php) or GeoLite2 CSV, then enter its path here"));
    } else if (!QFile::exists(dbPath_)) {
        picker_->setClickable(false);
        dbPathItem_->setPrompt(tr("File not found — country rules are off"));
    } else {
        picker_->setClickable(loggedIn_);
        dbPathItem_->setPrompt(tr("Database selected"));
    }
}

} // namespace PreferencesWindow
