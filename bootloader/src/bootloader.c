// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "inc/keys.h"

const uint8_t aes_key[] = AES_KEY;
const uint8_t rsa_public_key[] = RSA_PUBLIC_KEY;

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32

#define RSA_SIGNATURE_SIZE 0x100
#define IV_SIZE 0x10

// Device metadata
uint16_t *fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t *fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led()
{
    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF))
    {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // Turn on the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

    // Wait
    SysCtlDelay(SysCtlClockGet() * 2);

    // Turn off the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}

int main(void)
{
    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF))
    {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1)
    {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE)
        {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        }
        else if (instruction == BOOT)
        {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}

void reject()
{
    uart_write(UART0, ERROR);
    SysCtlReset();
    return;
}

/*
 * Load the firmware into flash.
 */
void load_firmware(void)
{
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;
    uint8_t rsa_signature[256];
    uint8_t iv[16];

    // Get message type.
    rcv = uart_read(UART0, BLOCKING, &read);
    uint16_t message_type = (uint16_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    message_type |= (uint16_t)rcv << 8;

    // Get version.
    rcv = uart_read(UART0, BLOCKING, &read);
    version = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    version |= (uint32_t)rcv << 8;

    // Get size.
    rcv = uart_read(UART0, BLOCKING, &read);
    size = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    size |= (uint32_t)rcv << 8;

    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF)
    {
        old_version = 1;
    }

    if (message_type != 0)
    {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }

    if (version != 0 && version < old_version)
    {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    }
    else if (version == 0)
    {
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *)METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART0, OK); // Acknowledge the metadata.

    for (int i = 0; i < IV_SIZE; i++)
    {
        rcv = uart_read(UART0, BLOCKING, &read);
        iv[i] = (uint8_t)rcv;
    }
    for (int i = 0; i < RSA_SIGNATURE_SIZE; i++)
    {
        rcv = uart_read(UART0, BLOCKING, &read);
        rsa_signature[i] = (uint8_t)rcv;
    }

    RsaKey rsa_public_key;
    wc_InitRsaKey(&rsa_public_key, NULL);
    wc_RsaPublicKeyDecode(rsa_public_key, sizeof(rsa_public_key), &rsa_public_key, 0);

    uint8_t data_header[2 + 2 + 2 + IV_SIZE];
    uint8_t *ptr = data_header;

    *(uint16_t *)ptr = message_type;
    ptr += sizeof(message_type);

    *(uint16_t *)ptr = version;
    ptr += sizeof(version);

    *(uint16_t *)ptr = size;
    ptr += sizeof(size);

    for (int i = 0; i < IV_SIZE; i++)
    {
        *ptr++ = iv[i];
    }

    uint8_t hash[SHA256_DIGEST_SIZE];
    wc_Sha256 sha256;
    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, data_header, sizeof(data_header));
    wc_Sha256Final(&sha256, hash);

    if (wc_RsaSSL_Verify(hash, sizeof(hash), rsa_signature, sizeof(rsa_signature), &rsa_public_key) != sizeof(hash))
    {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }

    uint16_t expected_frame_index = 0;

    /* Loop here until you can get all your characters and stuff */
    while (1)
    {
        uint16_t frame_index;
        uint16_t frame_message_type;
        uint16_t frame_length;
        uint8_t frame_rsa_signature[RSA_SIGNATURE_SIZE];

        // Read frame index
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_index = (uint16_t)rcv;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_index |= (uint16_t)rcv << 8;

        // Read message type
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_message_type = (uint16_t)rcv;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_message_type |= (uint16_t)rcv << 8;

        // Read frame length
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (uint16_t)rcv;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length |= (uint16_t)rcv << 8;

        // Handle zero-length frame
        if (frame_length == 0)
        {
            uart_write(UART0, OK); // Acknowledge the zero-length frame
            break; // Exit the loop, finish the update process
        }

        // Handle other frames
        if (frame_index != expected_frame_index)
        {
            uart_write(UART0, ERROR);
            SysCtlReset();
            return;
        }

        if (frame_message_type != 1)
        {
            uart_write(UART0, ERROR);
            SysCtlReset();
            return;
        }

        // Read RSA signature
        for (int i = 0; i < RSA_SIGNATURE_SIZE; i++)
        {
            rcv = uart_read(UART0, BLOCKING, &read);
            frame_rsa_signature[i] = (uint8_t)rcv;
        }

        // Read encrypted data
        unsigned char encrypted_data[FLASH_PAGESIZE];
        for (int i = 0; i < frame_length; i++)
        {
            rcv = uart_read(UART0, BLOCKING, &read);
            encrypted_data[i] = (uint8_t)rcv;
        }

        // Verify RSA signature
        wc_Sha256 sha256;
        wc_InitSha256(&sha256);
        wc_Sha256Update(&sha256, encrypted_data, frame_length);
        wc_Sha256Final(&sha256, hash);

        if (wc_RsaSSL_Verify(hash, sizeof(hash), frame_rsa_signature, sizeof(frame_rsa_signature), &rsa_public_key) != sizeof(hash))
        {
            uart_write(UART0, ERROR);
            SysCtlReset();
            return;
        }

        // Decrypt data
        Aes aes;
        uint8_t decrypted_data[FLASH_PAGESIZE];
        wc_AesInit(&aes, NULL, 0);
        wc_AesCbcDecrypt(&aes, decrypted_data, encrypted_data, frame_length, iv);

        // Write data to flash
        program_flash((uint8_t *)page_addr, decrypted_data, FLASH_PAGESIZE);

        page_addr += FLASH_PAGESIZE;
        expected_frame_index++;
    }

    uart_write(UART0, OK); // Acknowledge the end of the update process
    boot_firmware();
}

void boot_firmware(void) {
    // Check if firmware loaded
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset();            // Reset device
        return;
    }

    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART0, (char *)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}

