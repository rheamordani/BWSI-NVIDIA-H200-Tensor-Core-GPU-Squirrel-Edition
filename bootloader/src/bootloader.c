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
#include "/home/hacker/NVIDIA-H200-Tensor-Core-GPU-Squirrel-Edition/bootloader/inc/keys.h"

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

#define IV_SIZE 16
#define FIRMWARE_SIZE 16


// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
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


int main(void) {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}


void reject(void){
    uart_write(UART0, ERROR);
    SysCtlReset();
    return;
}

// recieve the frames 


 /*
 * Load the firmware into flash.
 */
void load_firmware(void) {
    int firmware_size = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t release_message_size = 0;
    uint32_t size = 0;
    volatile byte iv[IV_SIZE];
    volatile byte metadata_hash[32];
    volatile char release_message[1024];

    for (int i = 0; i < 1024; i++){
        release_message[i] = 0;
    }

    // BEGIN FRAME STRUCTURE
    // |                    |                 |                 |                                     |
    // | version (2 bytes)  |  size (2 bytes) |  iv (16 bytes)  |  sha256 hash of metadata (32 bytes) | 
    // |                    |                 |                 |                                     |

    // Get release_message_size.
    rcv = uart_read(UART0, BLOCKING, &read);
    release_message_size = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    release_message_size |= (uint32_t)rcv << 8;

    for (int i = 0; i < release_message_size; i++){
        release_message [i] = uart_read(UART0, BLOCKING, &read);
    }
    release_message[release_message_size + 1] = '\0';

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

    // Get IV used for AES CBC
    for (int j = 0; j < FIRMWARE_SIZE; j++) {
        rcv = uart_read(UART0, BLOCKING, &read);
        iv [j] = (uint8_t)rcv;
    }

    // Get sha 256 hash of metadata
    for (int j = 0; j < 32; j++) {
        rcv = uart_read(UART0, BLOCKING, &read);
        metadata_hash [j] = (uint8_t)rcv;
    }


    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);
    
    

    uint8_t metadata_buffer[4];
    metadata_buffer[0] = (uint8_t)(version & 0xFF);
    metadata_buffer[1] = (uint8_t)((version >> 8) & 0xFF);
    metadata_buffer[2] = (uint8_t)(size & 0xFF);
    metadata_buffer[3] = (uint8_t)((size >> 8) & 0xFF);

    uint8_t metadata_received_hash[32];
    wc_Sha256Hash(metadata_buffer, sizeof(metadata_buffer), metadata_received_hash);

    // Compare the computed hash with the received hash
    if (memcmp(metadata_hash, metadata_received_hash, sizeof(metadata_hash)) != 0) {
        uart_write(UART0, ERROR); // Reject the firmware
        SysCtlReset();            // Reset device
        return;
    }

    uart_write(UART0, OK); // Acknowledge the metadata.

    /* Loop here until you can get all your characters and stuff */
    volatile uint32_t size_firmware = 256;
    byte decrypted_firmware_hash[32];
    uint8_t fw_buffer [FIRMWARE_SIZE];
    volatile uint32_t num_frames = 0;
    uint32_t frame_counter = 0;
    volatile uint32_t size_frame = 0;
    volatile firmware_hash [32];

    num_frames = size / 16;
    if (num_frames % 16 != 0){
        num_frames += 1;
    } 

    while (1) {
        frame_counter += 1;

        // Get two bytes for the length.
        for (int i = 0; i < 2; i++){
            fw_buffer [i] = uart_read(UART0, BLOCKING, &read);
        }
        if (fw_buffer[0] == 0 && fw_buffer[1] == 0){
            size_firmware = 0;
        }else{
            for (int i = 2; i < 16; i++){
                fw_buffer [i] = uart_read(UART0, BLOCKING, &read);
            }
            for (int i = 0; i < 32; i++){
                firmware_hash [i] = uart_read(UART0, BLOCKING, &read);
            }

            Aes dec;
            volatile int ret;
            wc_AesInit(&dec, NULL, INVALID_DEVID);

            // Set the IV
            wc_AesSetIV(&dec, iv);

            // Set the key for decryption
            char decrypted_firmware[FIRMWARE_SIZE];
            for (int i = 0; i < FIRMWARE_SIZE; i++){
                decrypted_firmware[i] = 1;
            }

            wc_AesSetKey(&dec, aes_key, 32, iv, AES_DECRYPTION);

            // Perform decryption
            ret = wc_AesCbcDecrypt(&dec, decrypted_firmware, fw_buffer, FIRMWARE_SIZE);
            if (ret != 0){
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            char last_frame_decrypted_firmware[256];

            uint8_t firmware_received_hash[32];
            wc_Sha256 sha;
            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, (const byte*)decrypted_firmware, sizeof(decrypted_firmware));
            wc_Sha256Final(&sha, firmware_received_hash);

            // Compute hash of the decrypted firmware
            uint8_t expected_hash[32];
            wc_Sha256Hash(decrypted_firmware, sizeof(decrypted_firmware), expected_hash);
            
            // Compare the computed hash with the received hash
            if (memcmp(firmware_received_hash, expected_hash, sizeof(firmware_received_hash)) != 0) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            if (num_frames == frame_counter){
                size_frame = size % 16;
                for (int i = 0; i < size_frame; i ++){
                    last_frame_decrypted_firmware[i] = decrypted_firmware[i];
                }
                for (int i = 0; i < size%16; ++i) {
                    data[data_index] = last_frame_decrypted_firmware[i];
                    data_index += 1;
                    if (data_index == FLASH_PAGESIZE) {
                        // Try to write flash and check for error
                        if (program_flash((uint8_t *) page_addr, data, data_index)) {
                            uart_write(UART0, ERROR); // Reject the firmware
                            SysCtlReset();            // Reset device
                            return;
                        }

                        // Update to next page
                        page_addr += FLASH_PAGESIZE;
                        data_index = 0;

                        // If at end of firmware, go to main
                        if (size_firmware == 0) {
                            uart_write(UART0, OK);
                            break;
                        }
                    }

                } // for
            } else {
                for (int i = 0; i < FIRMWARE_SIZE; ++i) {
                    data[data_index] = decrypted_firmware[i];
                    data_index += 1;
                    if (data_index == FLASH_PAGESIZE) {
                        // Try to write flash and check for error
                        if (program_flash((uint8_t *) page_addr, data, data_index)) {
                            uart_write(UART0, ERROR); // Reject the firmware
                            SysCtlReset();            // Reset device
                            return;
                        }

                        // Update to next page
                        page_addr += FLASH_PAGESIZE;
                        data_index = 0;

                        // If at end of firmware, go to main
                        if (size_firmware == 0) {
                            uart_write(UART0, OK);
                            break;
                        }
                    }
                } // for
            }
        }


        if (size_firmware == 0) {
            // Try to write flash and check for error
            for (int i = 0; i < release_message_size+1; ++i) {
                data[data_index] = release_message[i];
                data_index += 1;
                if (data_index == FLASH_PAGESIZE) {
                    // Try to write flash and check for error
                    if (program_flash((uint8_t *) page_addr, data, data_index)) {
                        uart_write(UART0, ERROR); // Reject the firmware
                        SysCtlReset();            // Reset device
                        return;
                    }

                    // Update to next page
                    page_addr += FLASH_PAGESIZE;
                    data_index = 0;
                }
            }
            if (program_flash((uint8_t *) page_addr, data, data_index)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // If at end of firmware, go to main
            if (size_firmware == 0) {
                uart_write(UART0, OK);
                return;
            }
        }

        uart_write(UART0, OK); // Acknowledge the frame.
    } // while(1)
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
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
    uart_write_str(UART0, "Booting NVIDIA-H200-Tensor-Core-GPU-Squirrel-Edition firmware\n");
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