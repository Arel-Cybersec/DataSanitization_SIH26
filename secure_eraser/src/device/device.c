/**
 * @file device.c
 * @brief StorageDevice initialisation and display helpers.
 */
#include "device/device.h"

#include <stdio.h>
#include <string.h>

void device_init(StorageDevice *dev)
{
    if (!dev) return;
    memset(dev, 0, sizeof(*dev));
    dev->device_type   = DEVICE_TYPE_UNKNOWN;
    dev->transport_type = TRANSPORT_UNKNOWN;
    dev->logical_sector_size  = 512U;
    dev->physical_sector_size = 512U;
}

const char *device_type_str(DeviceType type)
{
    switch (type) {
        case DEVICE_TYPE_HDD:       return "HDD (rotational)";
        case DEVICE_TYPE_SATA_SSD:  return "SATA SSD";
        case DEVICE_TYPE_NVME_SSD:  return "NVMe SSD";
        case DEVICE_TYPE_USB_HDD:   return "USB HDD";
        case DEVICE_TYPE_USB_SSD:   return "USB SSD";
        case DEVICE_TYPE_USB_FLASH: return "USB Flash";
        case DEVICE_TYPE_SD_CARD:   return "SD/Memory Card";
        default:                    return "Unknown";
    }
}

const char *device_transport_str(TransportType transport)
{
    switch (transport) {
        case TRANSPORT_SATA:    return "SATA";
        case TRANSPORT_NVME:    return "NVMe";
        case TRANSPORT_USB:     return "USB";
        case TRANSPORT_SD:      return "SD";
        default:                return "Unknown";
    }
}

const char *sanitization_method_str(SanitizationMethod method)
{
    switch (method) {
        case SANITIZE_METHOD_BLOCK_ERASE:   return "Block Erase (pattern overwrite)";
        case SANITIZE_METHOD_CRYPTO_ERASE:  return "Cryptographic Erase (key destruction)";
        case SANITIZE_METHOD_DEVICE_NATIVE: return "Device-Native Sanitize";
        default:                            return "None";
    }
}

void device_print_info(const StorageDevice *dev)
{
    if (!dev) return;

    double capacity_gb = (double)dev->capacity_bytes / (1024.0 * 1024.0 * 1024.0);

    printf("  Path           : %s\n",      dev->path[0]   ? dev->path   : "(none)");
    printf("  Model          : %s\n",      dev->model[0]  ? dev->model  : "(unknown)");
    printf("  Serial         : %s\n",      dev->serial[0] ? dev->serial : "(unknown)");
    printf("  Capacity       : %.2f GiB (%llu bytes)\n",
           capacity_gb, (unsigned long long)dev->capacity_bytes);
    printf("  Logical BS     : %u bytes\n",   dev->logical_sector_size);
    printf("  Physical BS    : %u bytes\n",   dev->physical_sector_size);
    printf("  Device Type    : %s\n",         device_type_str(dev->device_type));
    printf("  Transport      : %s\n",         device_transport_str(dev->transport_type));
    printf("  Rotational     : %s\n",         dev->is_rotational ? "yes" : "no");
    printf("  Removable      : %s\n",         dev->is_removable  ? "yes" : "no");
    printf("  Read-Only      : %s\n",         dev->is_read_only  ? "yes" : "no");
    printf("  Block Erase    : %s\n",
           dev->capabilities.supports_block_erase  ? "supported" : "not supported");
    printf("  Crypto Erase   : %s\n",
           dev->capabilities.supports_crypto_erase ? "supported" : "not supported");
    printf("  Native Sanitize: %s\n",
           dev->capabilities.supports_device_native ? "supported" : "not supported");
}
