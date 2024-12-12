<?php

namespace Furbyus\Hashing\Crc;

final class CrcPolynomials
{
    const CRC_8 = 0x07; //SMBus, iButton
    const CRC_16_CCITT = 0x1021; //X.25, Bluetooth, PPP
    const CRC_16_IBM = 0x8005; //Redes de almacenamiento
    const CRC_32 = 0x04C11DB7; //Ethernet, ZIP, PNG
    const CRC_32_TS = 0x04C11DB7; //Transport Stream, MP4 Ogg
    const CRC_32C = 0x1EDC6F41; //iSCSI, redes
    const CRC_64_ISO = 0x42F0E1EBA9EA3693; //Almacenamiento de alto rendimiento

}