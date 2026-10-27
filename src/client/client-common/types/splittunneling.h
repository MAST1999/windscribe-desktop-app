#pragma once

#include <algorithm>

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QSettings>
#include <QVector>

#include "types/enums.h"
#include "utils/log/categories.h"
#include "utils/networkingvalidation.h"

namespace types {


struct SplitTunnelingSettings
{
    SplitTunnelingSettings() = default;

    SplitTunnelingSettings(const QJsonObject &json)
    {
        if (json.contains(kJsonActiveProp) && json[kJsonActiveProp].isBool()) {
            active = json[kJsonActiveProp].toBool();
        }

        if (json.contains(kJsonModeProp) && json[kJsonModeProp].isDouble()) {
            mode = enumFromInt<SPLIT_TUNNELING_MODE>(json[kJsonModeProp].toInt());
        }
    }

    bool active = false;
    SPLIT_TUNNELING_MODE mode = SPLIT_TUNNELING_MODE_EXCLUDE;

    bool operator==(const SplitTunnelingSettings &other) const
    {
        return other.active == active &&
               other.mode == mode;
    }

    bool operator!=(const SplitTunnelingSettings &other) const
    {
        return !(*this == other);
    }

    QJsonObject toJson(bool isForDebugLog) const
    {
        QJsonObject json;
        json[kJsonActiveProp] = active;
        json[kJsonModeProp] = static_cast<int>(mode);
        if (isForDebugLog) {
            json["modeDesc"] = enumToString(mode);
        }
        return json;
    }

    friend QDataStream& operator <<(QDataStream &stream, const SplitTunnelingSettings &o)
    {
        stream << versionForSerialization_;
        stream << o.active << o.mode;
        return stream;
    }

    friend QDataStream& operator >>(QDataStream &stream, SplitTunnelingSettings &o)
    {
        quint32 version;
        stream >> version;
        if (version > o.versionForSerialization_) {
            stream.setStatus(QDataStream::ReadCorruptData);
            return stream;
        }
        stream >> o.active >> o.mode;
        return stream;
    }

    void validate()
    {
        mode = enumFromInt<SPLIT_TUNNELING_MODE>(static_cast<int>(mode));
    }

private:
    static const inline QString kJsonActiveProp = "active";
    static const inline QString kJsonModeProp = "mode";

    static constexpr quint32 versionForSerialization_ = 1;  // should increment the version if the data format is changed
};

struct SplitTunnelingNetworkRoute
{
    // Max length of a domain-regex pattern (bounds compile cost and IPC size).
    static constexpr int kMaxRegexLen = 512;

    SPLIT_TUNNELING_NETWORK_ROUTE_TYPE type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_IP;
    QString name;
    bool active = true;

    SplitTunnelingNetworkRoute() : type(SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_IP) {}

    SplitTunnelingNetworkRoute(const QJsonObject &json)
    {
        if (json.contains(kJsonTypeProp) && json[kJsonTypeProp].isDouble()) {
            type = enumFromInt<SPLIT_TUNNELING_NETWORK_ROUTE_TYPE>(json[kJsonTypeProp].toInt());
        }

        if (json.contains(kJsonNameProp) && json[kJsonNameProp].isString()) {
            name = json[kJsonNameProp].toString();
        }

        if (json.contains(kJsonActiveProp) && json[kJsonActiveProp].isBool()) {
            active = json[kJsonActiveProp].toBool();
        } else {
            active = true;
        }
    }

    bool operator==(const SplitTunnelingNetworkRoute &other) const
    {
        return other.type == type &&
               other.name == name &&
               other.active == active;
    }

    bool operator!=(const SplitTunnelingNetworkRoute &other) const
    {
        return !(*this == other);
    }

    QJsonObject toJson() const
    {
        QJsonObject json;
        json[kJsonTypeProp] = static_cast<int>(type);
        json[kJsonNameProp] = name;
        json[kJsonActiveProp] = active;
        return json;
    }

    friend QDataStream& operator <<(QDataStream &stream, const SplitTunnelingNetworkRoute &o)
    {
        stream << versionForSerialization_;
        stream << o.type << o.name << o.active;
        return stream;
    }

    friend QDataStream& operator >>(QDataStream &stream, SplitTunnelingNetworkRoute &o)
    {
        quint32 version;
        stream >> version;
        if (version > o.versionForSerialization_) {
            stream.setStatus(QDataStream::ReadCorruptData);
            return stream;
        }
        stream >> o.type >> o.name;

        if (version >= 2) {
            stream >> o.active;
        } else {
            o.active = true;
        }
        return stream;
    }

    bool isValidName() const
    {
        switch (type) {
        case SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_IP:
            return NetworkingValidation::isIpCidr(name);
        case SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY:
            return NetworkingValidation::isCountryCode(name);
        case SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_DOMAIN_REGEX:
            // Structural check only; RE2-parse validation happens where RE2 is linked (GUI entry
            // and Phase-2 enforcement). Bounds + printable single line keep garbage out of IPC.
            return !name.isEmpty() && name.size() <= kMaxRegexLen &&
                   !name.contains(QChar(0)) && NetworkingValidation::isPrintableSingleLineAscii(name);
        case SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_HOSTNAME:
        default:
            return NetworkingValidation::isDomain(name);
        }
    }

    void validate()
    {
        type = enumFromInt<SPLIT_TUNNELING_NETWORK_ROUTE_TYPE>(static_cast<int>(type));
        if (name.isEmpty()) {
            return;
        }
        if (type == SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY) {
            name = name.toLower();
            return;
        }
        if (type == SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_DOMAIN_REGEX) {
            return;
        }
        // The name shape is authoritative for the two legacy kinds; a mismatched declared type is
        // corrected. New kinds are trusted (a regex/country string is not shape-detectable).
        if (NetworkingValidation::isIpCidr(name)) {
            type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_IP;
        } else {
            type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_HOSTNAME;
        }
    }

private:
    static const inline QString kJsonTypeProp = "type";
    static const inline QString kJsonNameProp = "name";
    static const inline QString kJsonActiveProp = "active";

    static constexpr quint32 versionForSerialization_ = 2;  // should increment the version if the data format is changed
};

struct SplitTunnelingApp
{
    SplitTunnelingApp() = default;
    SplitTunnelingApp& operator=(const SplitTunnelingApp&) = default;

    SplitTunnelingApp(const QJsonObject &json)
    {
        if (json.contains(kJsonIsRegexProp) && json[kJsonIsRegexProp].isBool()) {
            isRegex = json[kJsonIsRegexProp].toBool();
        }

        if (json.contains(kJsonTypeProp) && json[kJsonTypeProp].isDouble()) {
            type = enumFromInt<SPLIT_TUNNELING_APP_TYPE>(json[kJsonTypeProp].toInt());
        }

        if (json.contains(kJsonNameProp) && json[kJsonNameProp].isString()) {
            name = json[kJsonNameProp].toString();
        }

        if (json.contains(kJsonFullNameProp) && json[kJsonFullNameProp].isString()) {
            QString path = json[kJsonFullNameProp].toString();
            if (isRegex) {
                // A regex entry's fullName is the pattern itself, never a file path: skip the
                // existence check entirely.
                fullName = path;
            } else {
#ifdef Q_OS_LINUX
                // Linux Flatpak entries store the app ID (e.g. org.mozilla.firefox) here, which has no
                // on-disk path. Only run the existence check for path-shaped values.
                const bool isPath = path.startsWith('/');
#else
                const bool isPath = true;
#endif
                if (!isPath || QFile::exists(path)) {
                    fullName = path;
                }
            }
        }

        if (json.contains(kJsonActiveProp) && json[kJsonActiveProp].isBool()) {
            active = json[kJsonActiveProp].toBool();
        } else {
            active = true;
        }

        if (json.contains(kJsonIconProp) && json[kJsonIconProp].isString()) {
            QString path = json[kJsonIconProp].toString();
            if (QFile::exists(path)) {
                icon = path;
            }
        }
    }

    bool active = true;
    QString fullName;   // path + name; for isRegex entries, the regex pattern itself
    QString name;
    QString icon;
    SPLIT_TUNNELING_APP_TYPE type = SPLIT_TUNNELING_APP_TYPE_USER;
    // True when fullName is a regex pattern matched against process paths, not a file path.
    bool isRegex = false;

    bool operator==(const SplitTunnelingApp &other) const
    {
        return other.type == type &&
               other.name == name &&
               other.fullName == fullName &&
               other.active == active &&
               other.icon == icon &&
               other.isRegex == isRegex;
    }

    bool operator!=(const SplitTunnelingApp &other) const
    {
        return !(*this == other);
    }

    QJsonObject toJson(bool isForDebugLog) const
    {
        QJsonObject json;
        json[kJsonActiveProp] = active;
        json[kJsonNameProp] = name;
        json[kJsonTypeProp] = static_cast<int>(type);
        if (isForDebugLog) {
            json["fullNameDesc"] = fullName.isEmpty() ? "empty" : "set";
            json["iconDesc"] = icon.isEmpty() ? "empty" : "set";
        } else {
            json[kJsonFullNameProp] = fullName;
            json[kJsonIconProp] = icon;
        }
        json[kJsonIsRegexProp] = isRegex;
        return json;
    }

    friend QDataStream& operator <<(QDataStream &stream, const SplitTunnelingApp &o)
    {
        stream << versionForSerialization_;
        stream << o.type << o.name << o.fullName << o.active << o.icon << o.isRegex;
        return stream;
    }

    friend QDataStream& operator >>(QDataStream &stream, SplitTunnelingApp &o)
    {
        quint32 version;
        stream >> version;
        if (version > o.versionForSerialization_) {
            stream.setStatus(QDataStream::ReadCorruptData);
            return stream;
        }
        stream >> o.type >> o.name >> o.fullName >> o.active;

        if (version >= 2) {
            stream >> o.icon;
        }
        if (version >= 3) {
            stream >> o.isRegex;
        } else {
            o.isRegex = false;
        }
        return stream;
    }

    void validate()
    {
        type = enumFromInt<SPLIT_TUNNELING_APP_TYPE>(static_cast<int>(type));
        if (isRegex) {
            // A regex entry's fullName is the pattern itself, not a filesystem path: path
            // cleanup would corrupt the pattern.
            return;
        }
        // The Windows file dialog returns forward slashes, while the app picker uses backslashes. Doubled or trailing
        // separators name the same app, so they are dropped for the duplicate check.
        fullName = QDir::toNativeSeparators(QDir::cleanPath(fullName));
    }

private:
    static const inline QString kJsonActiveProp = "active";
    static const inline QString kJsonFullNameProp = "fullName";
    static const inline QString kJsonNameProp = "name";
    static const inline QString kJsonIconProp = "icon";
    static const inline QString kJsonTypeProp = "type";
    static const inline QString kJsonIsRegexProp = "isRegex";

    static constexpr quint32 versionForSerialization_ = 3;  // should increment the version if the data format is changed
};


struct SplitTunneling
{
    static constexpr int kMaxApps = 50;
    static constexpr int kMaxHostnames = 50;
    static constexpr int kMaxIpRoutes = 4096;
    static constexpr int kMaxStringLen = 4096;
    // New-rule-kind caps. Countries are destination sets expanded kernel-side (each adds thousands
    // of nft set elements), so the cap is tight; regex patterns are cheap but bounded anyway.
    // kMaxRegexRules bounds process + domain regexes COMBINED (compile cost and classifier load).
    static constexpr int kMaxRegexRules = 100;
    static constexpr int kMaxCountryRules = 10;
    static constexpr int kMaxDomainRegexRules = 100;

    SplitTunneling() = default;

    SplitTunneling(const QJsonObject &json)
    {
        if (json.contains(kJsonSettingsProp) && json[kJsonSettingsProp].isObject()) {
            settings = SplitTunnelingSettings(json[kJsonSettingsProp].toObject());
        }

        if (json.contains(kJsonAppsProp) && json[kJsonAppsProp].isArray()) {
            QJsonArray appsArray = json[kJsonAppsProp].toArray();
            apps.clear();
            apps.reserve(appsArray.size());
            for (const QJsonValue &appValue : appsArray) {
                if (appValue.isObject()) {
                    apps.append(SplitTunnelingApp(appValue.toObject()));
                }
            }
        }

        if (json.contains(kJsonNetworkRoutesProp) && json[kJsonNetworkRoutesProp].isArray()) {
            QJsonArray networkRoutesArray = json[kJsonNetworkRoutesProp].toArray();
            networkRoutes.clear();
            networkRoutes.reserve(networkRoutesArray.size());
            for (const QJsonValue &routeValue : networkRoutesArray) {
                if (routeValue.isObject()) {
                    networkRoutes.append(SplitTunnelingNetworkRoute(routeValue.toObject()));
                }
            }
        }
    }

    SplitTunnelingSettings settings;
    QVector<SplitTunnelingApp> apps;
    QVector<SplitTunnelingNetworkRoute> networkRoutes;
    // Path to a user-provided GeoIP database file (DB-IP LITE / GeoLite2 CSV). Linux only; empty
    // disables country rules. Read by the helper, which parses and caches the contents.
    QString geoipDatabasePath;

    bool operator==(const SplitTunneling &other) const
    {
        return other.settings == settings &&
               other.apps == apps &&
               other.networkRoutes == networkRoutes &&
               other.geoipDatabasePath == geoipDatabasePath;
    }

    bool operator!=(const SplitTunneling &other) const
    {
        return !(*this == other);
    }

#ifdef CLI_ONLY
    void fromIni(const QSettings &s)
    {
        const SplitTunnelingSettings defaults;
        settings.active = s.value(kIniSplitTunnelingEnabledProp, defaults.active).toBool();
        settings.mode = enumFromString<SPLIT_TUNNELING_MODE>(s.value(kIniSplitTunnelingModeProp, enumToString(defaults.mode)).toString());

        apps.clear();
        const QStringList appsList = s.value(kIniSplitTunnelingAppsProp).toStringList();
        for (auto appPath : appsList) {
            if (appPath.isEmpty()) {
                continue;
            }
            if (appPath.startsWith(kIniRegexPrefix)) {
                // Regex app entry: fullName is the pattern, never a file path.
                SplitTunnelingApp a;
                a.active = true;
                a.isRegex = true;
                a.fullName = appPath.mid(kIniRegexPrefix.length());
                a.name = a.fullName;
                a.icon = "";
                a.type = SPLIT_TUNNELING_APP_TYPE_USER;
                apps << a;
                continue;
            }
#ifdef Q_OS_LINUX
            // Linux Flatpak entries store the app ID (e.g. org.mozilla.firefox) here, which has
            // no on-disk path. Only run the existence check for path-shaped values.
            const bool isPath = appPath.startsWith('/');
#else
            const bool isPath = true;
#endif
            if (isPath) {
                if (!QFile::exists(appPath)) {
                    qCDebug(LOG_BASIC) << "Skipping non-existent split tunneling app '" << appPath << "'";
                    continue;
                }
            }

            SplitTunnelingApp a;
            a.active = true;
            a.fullName = appPath;
            a.name = appPath;
            a.icon = "";
            a.type = SPLIT_TUNNELING_APP_TYPE_USER;
            apps << a;
        }

        networkRoutes.clear();
        const QStringList networkRoutesList = s.value(kIniSplitTunnelingRoutesProp).toStringList();
        for (auto route : networkRoutesList) {
            if (route.isEmpty()) {
                continue;
            }
            SplitTunnelingNetworkRoute r;
            if (route.startsWith(kIniCountryPrefix)) {
                r.type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY;
                r.name = route.mid(kIniCountryPrefix.length()).toLower();
            } else if (route.startsWith(kIniRegexPrefix)) {
                r.type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_DOMAIN_REGEX;
                r.name = route.mid(kIniRegexPrefix.length());
            } else if (NetworkingValidation::isIpCidr(route)) {
                r.type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_IP;
                r.name = route;
            } else {
                r.type = SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_HOSTNAME;
                r.name = route;
            }
            networkRoutes << r;
        }

        geoipDatabasePath = s.value(kIniSplitTunnelingGeoIpDatabaseProp, geoipDatabasePath).toString();
    }

    void toIni(QSettings &s) const
    {
        s.setValue(kIniSplitTunnelingEnabledProp, settings.active);
        s.setValue(kIniSplitTunnelingModeProp, enumToString(settings.mode));

        QStringList appsList;
        for (auto app : apps) {
            if (app.active) {
                appsList << (app.isRegex ? (kIniRegexPrefix + app.fullName) : app.fullName);
            }
        }
        if (appsList.isEmpty()) {
            s.setValue(kIniSplitTunnelingAppsProp, "");
        } else {
            s.setValue(kIniSplitTunnelingAppsProp, appsList);
        }

        QStringList routesList;
        for (auto route : networkRoutes) {
            if (route.active) {
                if (route.type == SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY) {
                    routesList << kIniCountryPrefix + route.name;
                } else if (route.type == SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_DOMAIN_REGEX) {
                    routesList << kIniRegexPrefix + route.name;
                } else {
                    routesList << route.name;
                }
            }
        }
        if (routesList.isEmpty()) {
            s.setValue(kIniSplitTunnelingRoutesProp, "");
        } else {
            s.setValue(kIniSplitTunnelingRoutesProp, routesList);
        }

        s.setValue(kIniSplitTunnelingGeoIpDatabaseProp, geoipDatabasePath);
    }
#endif

    QJsonObject toJson(bool isForDebugLog) const
    {
        QJsonObject json;
        json[kJsonSettingsProp] = settings.toJson(isForDebugLog);

        QJsonArray appsArray;
        for (const SplitTunnelingApp& app : apps) {
            appsArray.append(app.toJson(isForDebugLog));
        }
        json[kJsonAppsProp] = appsArray;

        QJsonArray networkRoutesArray;
        for (const SplitTunnelingNetworkRoute& route : networkRoutes) {
            networkRoutesArray.append(route.toJson());
        }
        json[kJsonNetworkRoutesProp] = networkRoutesArray;

        json[kJsonGeoIpDatabasePathProp] = geoipDatabasePath;

        return json;
    }

    friend QDataStream& operator <<(QDataStream &stream, const SplitTunneling &o)
    {
        stream << versionForSerialization_;
        stream << o.settings << o.apps << o.networkRoutes << o.geoipDatabasePath;
        return stream;
    }

    friend QDataStream& operator >>(QDataStream &stream, SplitTunneling &o)
    {
        quint32 version;
        stream >> version;
        if (version > o.versionForSerialization_) {
            stream.setStatus(QDataStream::ReadCorruptData);
            return stream;
        }
        stream >> o.settings >> o.apps >> o.networkRoutes;
        if (version >= 2) {
            stream >> o.geoipDatabasePath;
        }
        return stream;
    }

    void validate()
    {
        settings.validate();

        QVector<SplitTunnelingApp> filteredApps;
        filteredApps.reserve(apps.size() < kMaxApps ? apps.size() : kMaxApps);
        int droppedAppsOverCap = 0;
        int droppedInvalidApps = 0;
        int numRegexApps = 0;
        for (SplitTunnelingApp &app : apps) {
            if (app.fullName.isEmpty()) {
                // App not found on this system (file existence check in constructor)
                continue;
            }
            if (app.fullName.size() > kMaxStringLen || app.name.size() > kMaxStringLen ||
                app.fullName.contains(QChar(0)) || app.name.contains(QChar(0))) {
                droppedInvalidApps++;
                continue;
            }
            if (app.isRegex && app.fullName.size() > SplitTunnelingNetworkRoute::kMaxRegexLen) {
                droppedInvalidApps++;
                continue;
            }
            app.validate();
            auto duplicate = std::find_if(filteredApps.begin(), filteredApps.end(),
                                          [&app](const SplitTunnelingApp &a) { return a.fullName == app.fullName; });
            if (duplicate != filteredApps.end()) {
                duplicate->active = duplicate->active || app.active;
                continue;
            }
            if (filteredApps.size() >= kMaxApps) {
                droppedAppsOverCap++;
                continue;
            }
            if (app.isRegex) {
                numRegexApps++;
            }
            filteredApps.append(app);
        }
        if (droppedInvalidApps > 0) {
            qCWarning(LOG_BASIC) << "SplitTunneling: dropped" << droppedInvalidApps << "apps with invalid path";
        }
        if (droppedAppsOverCap > 0) {
            qCWarning(LOG_BASIC) << "SplitTunneling: apps over cap, dropped" << droppedAppsOverCap << "apps";
        }
        apps = filteredApps;

        QVector<SplitTunnelingNetworkRoute> filteredRoutes;
        const int maxRoutes = kMaxHostnames + kMaxIpRoutes + kMaxCountryRules + kMaxDomainRegexRules;
        filteredRoutes.reserve(networkRoutes.size() < maxRoutes ? networkRoutes.size() : maxRoutes);
        int numHostnames = 0;
        int numIpRoutes = 0;
        int numCountries = 0;
        int numDomainRegexes = 0;
        int droppedHostnamesOverCap = 0;
        int droppedIpRoutesOverCap = 0;
        int droppedCountriesOverCap = 0;
        int droppedDomainRegexesOverCap = 0;
        int droppedInvalidRoutes = 0;
        for (SplitTunnelingNetworkRoute &r : networkRoutes) {
            if (!r.isValidName()) {
                droppedInvalidRoutes++;
                continue;
            }

            if (r.type == SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_COUNTRY) {
                if (numCountries >= kMaxCountryRules) {
                    droppedCountriesOverCap++;
                    continue;
                }
                numCountries++;
            } else if (r.type == SPLIT_TUNNELING_NETWORK_ROUTE_TYPE_DOMAIN_REGEX) {
                // Combined cap with process regexes: the two kinds share the classifier budget
                // (spec §5.1 kMaxRegexRules). kMaxDomainRegexRules (the same value) exists for the
                // single-kind case; the combined check subsumes it.
                if (numDomainRegexes + numRegexApps >= kMaxRegexRules) {
                    droppedDomainRegexesOverCap++;
                    continue;
                }
                numDomainRegexes++;
            } else if (NetworkingValidation::isDomain(r.name)) {
                if (numHostnames >= kMaxHostnames) {
                    droppedHostnamesOverCap++;
                    continue;
                }
                numHostnames++;
            } else {
                if (numIpRoutes >= kMaxIpRoutes) {
                    droppedIpRoutesOverCap++;
                    continue;
                }
                numIpRoutes++;
            }

            r.validate();
            filteredRoutes.append(r);
        }
        if (droppedInvalidRoutes > 0) {
            qCWarning(LOG_BASIC) << "SplitTunneling: dropped" << droppedInvalidRoutes << "routes with invalid name";
        }
        if (droppedHostnamesOverCap > 0) {
            qCWarning(LOG_BASIC) << "SplitTunneling: hostnames over cap, dropped" << droppedHostnamesOverCap << "routes";
        }
        if (droppedIpRoutesOverCap > 0) {
            qCWarning(LOG_BASIC) << "SplitTunneling: IP routes over cap, dropped" << droppedIpRoutesOverCap << "routes";
        }
        if (droppedCountriesOverCap > 0) {
            qCWarning(LOG_BASIC) << "SplitTunneling: countries over cap, dropped" << droppedCountriesOverCap << "routes";
        }
        if (droppedDomainRegexesOverCap > 0) {
            qCWarning(LOG_BASIC) << "SplitTunneling: domain regexes over cap, dropped" << droppedDomainRegexesOverCap << "routes";
        }
        networkRoutes = filteredRoutes;
    }

private:
    static const inline QString kIniSplitTunnelingAppsProp = "SplitTunnelingApps";
    static const inline QString kIniSplitTunnelingRoutesProp = "SplitTunnelingRoutes";
    static const inline QString kIniSplitTunnelingEnabledProp = "SplitTunnelingEnabled";
    static const inline QString kIniSplitTunnelingModeProp = "SplitTunnelingMode";
    static const inline QString kIniSplitTunnelingGeoIpDatabaseProp = "SplitTunnelingGeoIpDatabase";
    // INI prefixes distinguishing the new rule kinds inside the flat routes string list.
    static const inline QString kIniCountryPrefix = "country:";
    static const inline QString kIniRegexPrefix = "re:";

    static const inline QString kJsonAppsProp = "apps";
    static const inline QString kJsonNetworkRoutesProp = "networkRoutes";
    static const inline QString kJsonSettingsProp = "settings";
    static const inline QString kJsonVersionProp = "version";
    static const inline QString kJsonGeoIpDatabasePathProp = "geoipDatabasePath";

    static constexpr quint32 versionForSerialization_ = 2;  // should increment the version if the data format is changed
};


} // types namespace
