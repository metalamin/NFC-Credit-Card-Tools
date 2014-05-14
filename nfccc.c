/*

Base on readnfccc 2.0 - by Renaud Lifchitz (renaud.lifchitz@oppida.fr)
License: distributed under GPL version 3 (http://www.gnu.org/licenses/gpl.html)

* Introduction:
Dirty tricks to parse the information.
Reads NFC credit card personal data


* Requirements:
libnfc (>= 1.7.0-rc7) and a suitable NFC reader (http://nfc-tools.org/index.php?title=Devices_compatibility_matrix)

* Compilation:
$ gcc nfccc.c -lnfc -o nfccc.out

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <nfc/nfc.h>

#define MAX_FRAME_LEN 300
#define verbose 0

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

nfc_context *context;
nfc_device *pnd;
nfc_target nt;
uint8_t abtRx[MAX_FRAME_LEN];
uint8_t abtTx[MAX_FRAME_LEN];
size_t szRx = sizeof(abtRx);
size_t szTx;
int result;



void show(size_t recvlg, uint8_t *recv)
{
  int i;
  printf("< ");
  for (i = 0; i < (int) recvlg; i++) {
    printf(ANSI_COLOR_BLUE"%02x "ANSI_COLOR_RESET, (unsigned int) recv[i]);
  }
  printf("\n");
}

void read_record(int SFI,int record)
{
	uint8_t RECORD_CMD[] = {0x00, 0xB2, 0x01, 0x0C, 0x00};
	int SFI_aux=(SFI << 3) | 4;
	//printf(" Read SFI %d(%#04x) record %d\n", SFI,SFI_aux, record);
	RECORD_CMD[2]=record;
	RECORD_CMD[3]=SFI_aux;
	result = nfc_initiator_transceive_bytes(pnd, RECORD_CMD, sizeof(RECORD_CMD), abtRx, sizeof(abtRx), 500);
	//show(result, abtRx);
}

void parse_info()
{
  int i,j;
  unsigned char *res, output[50];
  /* Look for cardholder name */
  res = abtRx;
  for (i = 0; i < (unsigned int) result - 1; i++) {
    if (*res == 0x5f && *(res + 1) == 0x20) {
      strncpy(output, res + 3, (int) * (res + 2));
      output[(int) * (res + 2)] = 0;
      printf("Nombre del titular : %s\n", output);
      break;
    }
    res++;
  }

  /* Look for PAN */
  res = abtRx;
  for (i = 0; i < (unsigned int) result - 1; i++) {
    if (*res == 0x5a && *(res + 1) == 0x08) {
      strncpy(output, res + 2, 8);
      output[9] = 0;
      printf("Primary Account Number :");

      for (j = 0; j < 8; j++) {
        if (j % 2 == 0) printf(" ");
          printf(ANSI_COLOR_GREEN"%02x", output[j] & 0xff);
      }
      printf(ANSI_COLOR_RESET"\n");
      //expiry = (output[10] + (output[9] << 8) + (output[8] << 16)) >> 4;
      //printf("Fecha de caducidad : %02x/20%02x\n\n", (expiry & 0xff), ((expiry >> 8) & 0xff));
      break;
    }
    res++;
  }
}

void brute_record()
{
	int i,j;
	unsigned char *res;
	printf("\n");
	for (i = 1; i <= 32; i++) {
		printf("SFI:%2d  =====\n",i);
		for (j = 0; j <= 255; j++) {
			read_record(i,j);
			res = abtRx;
			int length= (int) result;
			if (*(res + length -2 ) == 0x90 && *(res +length-1) == 0x00) {
				printf("SFI:%d     record:%d    \n",i,j);
				parse_info();
				if (verbose) show(result, abtRx);
				//break;
			}
		}
	}
}

int main(int argc, char **argv){
	
	uint8_t SELECT_PAY2[] = {0x00, 0xA4, 0x04, 0x00, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0x00};
	uint8_t SELECT_APP_INIT[] = {0x00, 0xA4, 0x04, 0x00};


	uint8_t GET_PROCESS_OPTIONS[] = {0x80,0xa8,0x00,0x00,0x02,0x83,0x00,0x00};



	unsigned char *res, output[50], c, amount[10], msg[100];
	unsigned int i, j, expiry, length; 
	extern int optopt;

 

  nfc_init(&context);
  if (context == NULL) {
    printf("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }
  const char *acLibnfcVersion = nfc_version();
  printf("Using libnfc %s\n", acLibnfcVersion);
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    printf("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  };
  printf("NFC reader: %s opened\n\n", nfc_device_get_name(pnd));

  
  const nfc_modulation nm = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
  };
  if (nfc_initiator_select_passive_target(pnd, nm, NULL, 0, &nt) <= 0) {
    nfc_perror(pnd, "START_14443A");
    return(1);
  }

  printf("Checking for 2PAY.SYS.DDF01 ...  ");
  if ((result = nfc_initiator_transceive_bytes(pnd, SELECT_PAY2, sizeof(SELECT_PAY2), abtRx, sizeof(abtRx), 500)) < 0) {
    nfc_perror(pnd, "SELECT_PAY2");
    return(1);
  }
  
  
  res = abtRx;
  if (*res == 0x6f) {
	  printf(ANSI_COLOR_GREEN"[Found!]\n"ANSI_COLOR_RESET);
	  for (i = 0; i < (unsigned int) result - 1; i++) {
		if (*res == 0x4f) {
			printf("=> AID: ");
			length=(int) * (res + 1);

			memcpy(output, res+1, length+1);
			output[length+1] = 0;
			for (j = 1; j <= length; j++) {
				printf("%02x ", (unsigned int) output[j]);
			}
			printf("\n\n");
			break;
		}
		res++;
	  }
  }
  else {
	  printf(ANSI_COLOR_RED"[Not Found!]\n"ANSI_COLOR_RESET);
	  return(1);
  }
  
  if (verbose) show(result, abtRx);
  
  
  //Select the AID
  printf("Select AID ...  ");
  uint8_t SELECT_APP[length+2+4];
  
  memcpy(SELECT_APP, SELECT_APP_INIT, 4);
  memcpy(SELECT_APP+4, output, length+1);

  //Select the APP
  if ((result = nfc_initiator_transceive_bytes(pnd, SELECT_APP, sizeof(SELECT_APP), abtRx, sizeof(abtRx), 500)) < 0) {
    nfc_perror(pnd, "SELECT_APP");
    return(1);
  }
  res = abtRx;
  if (*res == 0x6f) printf(ANSI_COLOR_GREEN"[OK]\n"ANSI_COLOR_RESET);
  else {
	  printf(ANSI_COLOR_RED"[Error]\n"ANSI_COLOR_RESET);
	  show(result, abtRx);
	  return(1);
  }
  
  if (verbose) show(result, abtRx);
  
  //Get Processing Options
  printf("Get Processing Options ...  ");
  if ((result = nfc_initiator_transceive_bytes(pnd, GET_PROCESS_OPTIONS, sizeof(GET_PROCESS_OPTIONS), abtRx, sizeof(abtRx), 500)) < 0) {
    nfc_perror(pnd, "GET_PROCESS_OPTIONS");
    return(1);
  }
  res = abtRx;
  length= (int) result;
  if (*(res + length -2 ) == 0x90 && *(res +length-1) == 0x00){
	  printf(ANSI_COLOR_GREEN"[OK]\n"ANSI_COLOR_RESET);
	  
  }
  else {
	  printf(ANSI_COLOR_RED"[Error]\n"ANSI_COLOR_RESET);
	  
	  return(0);
  }
	  
  if (verbose) show(result, abtRx);
  
  //TODO: AFL parser so we don't need to brute force the records
  brute_record();
  
  

  nfc_close(pnd);
  nfc_exit(context);

  return(0);
}


