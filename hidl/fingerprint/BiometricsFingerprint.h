/*
 * Copyright (C) 2022 The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <android-base/properties.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android/hardware/biometrics/fingerprint/2.1/types.h>
#include <android/hardware/biometrics/fingerprint/2.2/IBiometricsFingerprintClientCallback.h>
#include <android/hardware/biometrics/fingerprint/2.3/IBiometricsFingerprint.h>
#include <fcntl.h>
#include <android/log.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <log/log.h>

#include <oplus/oplus_display_panel.h>
#include <vendor/oplus/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>

namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {
namespace V2_3 {
namespace implementation {

using ::android::sp;
using ::android::base::GetProperty;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintError;
using ::android::hardware::biometrics::fingerprint::V2_1::RequestStatus;
using ::android::hardware::biometrics::fingerprint::V2_2::FingerprintAcquiredInfo;
using ::android::hardware::biometrics::fingerprint::V2_2::IBiometricsFingerprintClientCallback;
using ::android::hardware::biometrics::fingerprint::V2_3::IBiometricsFingerprint;

using IOplusBiometricsFingerprint =
        vendor::oplus::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint;
using ::vendor::oplus::hardware::biometrics::fingerprint::V2_1::
        IBiometricsFingerprintClientCallbackEx;

class BiometricsFingerprint : public IBiometricsFingerprint,
                              public IBiometricsFingerprintClientCallback,
                              public IBiometricsFingerprintClientCallbackEx {
  public:
    BiometricsFingerprint();

    // Methods from ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint
    // follow.
    Return<uint64_t> setNotify(
            const sp<V2_1::IBiometricsFingerprintClientCallback>& clientCallback) override;
    Return<uint64_t> preEnroll() override;
    Return<RequestStatus> enroll(const hidl_array<uint8_t, 69>& hat, uint32_t gid,
                                 uint32_t timeoutSec) override;
    Return<RequestStatus> postEnroll() override;
    Return<uint64_t> getAuthenticatorId() override;
    Return<RequestStatus> cancel() override;
    Return<RequestStatus> enumerate() override;
    Return<RequestStatus> remove(uint32_t gid, uint32_t fid) override;
    Return<RequestStatus> setActiveGroup(uint32_t gid, const hidl_string& storePath) override;
    Return<RequestStatus> authenticate(uint64_t operationId, uint32_t gid) override;

    // Methods from ::android::hardware::biometrics::fingerprint::V2_3::IBiometricsFingerprint
    // follow.
    Return<bool> isUdfps(uint32_t sensorID) override;
    Return<void> onFingerDown(uint32_t x, uint32_t y, float minor, float major) override;
    Return<void> onFingerUp() override;

    // Methods from
    // ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback
    // follow.
    Return<void> onEnrollResult(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                                uint32_t remaining) override;
    Return<void> onAcquired(uint64_t deviceId, V2_1::FingerprintAcquiredInfo acquiredInfo,
                            int32_t vendorCode) override;
    Return<void> onAuthenticated(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                                 const hidl_vec<uint8_t>& token) override;
    Return<void> onError(uint64_t deviceId, FingerprintError error, int32_t vendorCode) override;
    Return<void> onRemoved(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                           uint32_t remaining) override;
    Return<void> onEnumerate(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                             uint32_t remaining) override;

    // Methods from
    // ::android::hardware::biometrics::fingerprint::V2_2::IBiometricsFingerprintClientCallback
    // follow.
    Return<void> onAcquired_2_2(uint64_t deviceId, FingerprintAcquiredInfo acquiredInfo,
                                int32_t vendorCode) override;

    // Methods from
    // ::vendor::oplus::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallbackEx
    // follow.
    Return<void> onEngineeringInfoUpdated(uint32_t lenth, const hidl_vec<uint32_t>& keys,
                                          const hidl_vec<hidl_string>& values) override;
    Return<void> onFingerprintCmd(int32_t cmdId, const hidl_vec<uint32_t>& result,
                                  uint32_t resultLen) override;

  private:
    bool ensureDisplayFd() {
        if (mOplusDisplayFd >= 0) {
            return true;
        }

        mOplusDisplayFd = open("/dev/oplus_display", O_RDWR);
        if (mOplusDisplayFd < 0) {
            if (!mDisplayFdOpenFailedLogged) {
                PLOG(WARNING) << "Failed to open /dev/oplus_display";
                mDisplayFdOpenFailedLogged = true;
            }
            return false;
        }

        LOG(INFO) << "Opened /dev/oplus_display fd=" << mOplusDisplayFd;
        mDisplayFdOpenFailedLogged = false;
        return true;
    }

    bool isUdfps() {
        const auto sensorType = GetProperty("persist.vendor.fingerprint.sensor_type", "");
        if (sensorType == "optical" || sensorType == "ultrasonic") {
            return true;
        }

        if (mOplusBiometricsFingerprint != nullptr) {
            const auto ret = mOplusBiometricsFingerprint->isUdfps(0 /* sensorId */);
            if (ret.isOk()) {
                return static_cast<bool>(ret);
            }
        }

        return false;
    }

    bool isUff() {
        return android::base::StartsWith(GetProperty("persist.vendor.fingerprint.version", ""),
                                         "UFF ");
    }

    bool panelIoctl(unsigned long request, unsigned int value, const char* name) {
        if (!ensureDisplayFd()) {
            return false;
        }

        if (ioctl(mOplusDisplayFd, request, &value) == 0) {
            return true;
        }

        PLOG(WARNING) << name << " ioctl failed with value=" << value;
        return false;
    }

    bool setHbm(unsigned int value) {
        return panelIoctl(PANEL_IOCTL_SET_HBM, value, "PANEL_IOCTL_SET_HBM");
    }

    bool setDimlayerHbm(unsigned int value) {
        return panelIoctl(PANEL_IOCTL_SET_DIMLAYER_HBM, value, "PANEL_IOCTL_SET_DIMLAYER_HBM");
    }

    bool setFpPress(unsigned int value) {
        return panelIoctl(PANEL_IOCTL_SET_FP_PRESS, value, "PANEL_IOCTL_SET_FP_PRESS");
    }

    sp<IOplusBiometricsFingerprint> mOplusBiometricsFingerprint;
    sp<V2_1::IBiometricsFingerprintClientCallback> mClientCallback;

    int mOplusDisplayFd;
    bool mDisplayFdOpenFailedLogged = false;
};

}  // namespace implementation
}  // namespace V2_3
}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
