/* capture_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture_globals.h"
#endif

#include "capture_preferences_frame.h"
#include <ui_capture_preferences_frame.h>
#include "wireshark_application.h"

#include <QSpacerItem>

#include "ui/capture_ui_utils.h"
#include "ui/ui_util.h"

#include <cstdio>
#include <epan/prefs-int.h>

CapturePreferencesFrame::CapturePreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::CapturePreferencesFrame)
{
    ui->setupUi(this);

    pref_device_ = prefFromPrefPtr(&prefs.capture_device);
    pref_prom_mode_ = prefFromPrefPtr(&prefs.capture_prom_mode);
    pref_pcap_ng_ = prefFromPrefPtr(&prefs.capture_pcap_ng);
    pref_real_time_ = prefFromPrefPtr(&prefs.capture_real_time);
    pref_auto_scroll_ = prefFromPrefPtr(&prefs.capture_auto_scroll);
    pref_show_info_ = prefFromPrefPtr(&prefs.capture_show_info);

    // Setting the left margin via a style sheet clobbers its
    // appearance.
    int margin = style()->pixelMetric(QStyle::PM_LayoutLeftMargin);
    QRect geom = ui->defaultInterfaceSpacer->geometry();
    geom.setWidth(margin);
    ui->defaultInterfaceSpacer->setGeometry(geom);
}

CapturePreferencesFrame::~CapturePreferencesFrame()
{
    delete ui;
}

void CapturePreferencesFrame::showEvent(QShowEvent *)
{
    updateWidgets();
}

void CapturePreferencesFrame::updateWidgets()
{
#ifdef HAVE_LIBPCAP
    interface_t device;

    ui->defaultInterfaceComboBox->clear();
    if (global_capture_opts.all_ifaces->len == 0) {
        /*
         * No interfaces - try refreshing the local interfaces, to
         * see whether any have showed up (or privileges have changed
         * to allow us to access them).
         */
        wsApp->refreshLocalInterfaces();
    }
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

        /* Continue if capture device is hidden */
        if (device.hidden) {
            continue;
        }
        ui->defaultInterfaceComboBox->addItem(QString((const char *)device.display_name));
    }

    if (pref_device_->stashed_val.string) {
        ui->defaultInterfaceComboBox->setEditText(pref_device_->stashed_val.string);
    } else {
        ui->defaultInterfaceComboBox->clearEditText();
    }

    ui->capturePromModeCheckBox->setChecked(pref_prom_mode_->stashed_val.boolval);
    ui->capturePcapNgCheckBox->setChecked(pref_pcap_ng_->stashed_val.boolval);
    ui->captureRealTimeCheckBox->setChecked(pref_real_time_->stashed_val.boolval);
    ui->captureAutoScrollCheckBox->setChecked(pref_auto_scroll_->stashed_val.boolval);
    ui->captureShowInfoCheckBox->setChecked(pref_show_info_->stashed_val.boolval);
#endif // HAVE_LIBPCAP
}

void CapturePreferencesFrame::on_defaultInterfaceComboBox_editTextChanged(const QString &new_iface)
{
    g_free((void *)pref_device_->stashed_val.string);
    pref_device_->stashed_val.string = g_strdup(new_iface.toUtf8().constData());
}

void CapturePreferencesFrame::on_capturePromModeCheckBox_toggled(bool checked)
{
    pref_prom_mode_->stashed_val.boolval = checked;
}

void CapturePreferencesFrame::on_capturePcapNgCheckBox_toggled(bool checked)
{
    pref_pcap_ng_->stashed_val.boolval = checked;
}

void CapturePreferencesFrame::on_captureRealTimeCheckBox_toggled(bool checked)
{
    pref_real_time_->stashed_val.boolval = checked;
}

void CapturePreferencesFrame::on_captureAutoScrollCheckBox_toggled(bool checked)
{
    pref_auto_scroll_->stashed_val.boolval = checked;
}

void CapturePreferencesFrame::on_captureShowInfoCheckBox_toggled(bool checked)
{
    pref_show_info_->stashed_val.boolval = checked;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
