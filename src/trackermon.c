#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define BUFFER_SIZE 256
#define THRESHOLD_SIZE 3
#define MAX_LENGTH 64
#define CONFIG_FILE "/etc/trackermon/config.conf"

/* Data Structure */
// Sample parser's data
struct funct_params_t {
	char log_file[MAX_LENGTH];
	char cpu_threshold[MAX_LENGTH];
	char mem_threshold[MAX_LENGTH];
	char network_threshold[MAX_LENGTH];
};

/*
 * Function that initializes the data before parsing
 * configuration file's  data
 */
void init_params(struct funct_params_t* params ) {
	strncpy(params->log_file, " ", MAX_LENGTH);
	strncpy(params->cpu_threshold, " ", MAX_LENGTH);
	strncpy(params->mem_threshold, " ", MAX_LENGTH);
	strncpy(params->network_threshold, " ", MAX_LENGTH);
}


/*********************************************************************/
/* Parsing  */

/*
 * Auxiliar function of the parser, deletes all the white spaces
 * of the buffer that reads the file
 */
char* delete_spaces(char* param ) {

	/* Initialize start, end pointers */
	char *start = param;
  char *end = &param[strlen(param) - 1];

	/* Delimit right side */
	while( (isspace (*end)) && (end >= start) )
		end--;
	*(end+1) = '\0';

	while ( (isspace (*start)) && (start < end) )
		start++;

	/* Copy finished data */
	strcpy (param, start);
	return param;
}


/*
 * Main parser function: makes all the logic of the parser
 * and sets the values founded in the sample structure
 *
 */
void parse_config(struct funct_params_t* params ) {

	char* _ss, _buff[BUFFER_SIZE];
	FILE* config_file = fopen(CONFIG_FILE, "r");
	if (config_file == NULL) return;

	/* Read next line */
	while ((_ss = fgets (_buff, sizeof _buff, config_file)) != NULL)
	{
		/* Skip blank lines and comments */
		if (_buff[0] == '\n' || _buff[0] == '#')
			continue;

		/* Parse name/value pair from line */
		char _key[MAX_LENGTH], _value[MAX_LENGTH];
		_ss = strtok(_buff, "=");

		if (_ss != NULL)
			strncpy (_key, _ss, MAX_LENGTH);
		_ss = strtok(NULL, "=");

		if (_ss != NULL)
			strncpy(_value, _ss, MAX_LENGTH);
		delete_spaces(_value);

		/* Copy into correct entry in parameters struct */
		if (strcmp(_key, "LOG_FILE") == 0)
			strncpy (params->log_file, _value, MAX_LENGTH);
		else if (strcmp(_key, "CPU_THRESHOLD") == 0)
			strncpy (params->cpu_threshold, _value, MAX_LENGTH);
		else if (strcmp(_key, "MEM_THRESHOLD") == 0)
			strncpy (params->mem_threshold, _value, MAX_LENGTH);
		else if (strcmp(_key, "NET_THRESHOLD") == 0)
			strncpy (params->network_threshold, _value, MAX_LENGTH);
	}
	/* Close file */
	fclose(config_file);
}



/**********************************************************************/

/* Main Function that initialize the daemon process
 * writes the data in the log file
 */

int main(int argc, char* argv[])  {

	struct funct_params_t _data;

  /* Initialize data */
	init_params(&_data);

  /* Read the config.conf file */
	printf("Reading configuration file...\n");
	parse_config(&_data);

	char _cpu[THRESHOLD_SIZE] = "";
	char _mem[THRESHOLD_SIZE] = "";
	char _net[THRESHOLD_SIZE] = "";

	int i;
	for(i = 0; i < THRESHOLD_SIZE; i++ ){
		if(_data.cpu_threshold[i] == '%' ) {	break; }
		else {_cpu[i] = _data.cpu_threshold[i];}
	}

	for(i = 0; i < THRESHOLD_SIZE; i++ ){
		if(_data.mem_threshold[i] == '%' ){ break; }
		else { _mem[i] = _data.mem_threshold[i]; }
	}

	for(i = 0; i < THRESHOLD_SIZE; i++ ){
		if(_data.network_threshold[i] == '%' ){ break; }
		else { _net[i] = _data.network_threshold[i]; }
	}

	/*****************************************************************************/

	FILE* _log = NULL;
	pid_t process_id = 0;


	// Create child process with the fork function
	process_id = fork();

	// Validation of fork failure
	if (process_id < 0)
	{
		printf("Process failed...\n");
		// Return failure in exit status
		exit(1);
	}
	// Kill the parent process and store de pid in a file
	if (process_id > 0)
	{
			_log = fopen(_data.log_file, "w+");
   		FILE* _child;
   		_child = fopen("/var/run/trackermon.pid", "w+");
   		fprintf(_child, "%d\n", process_id );
   		fclose(_child);

	// return success in exit status
		exit(0);
	}

	// Open a log file in write mode.
	//with the path specified in the configuration file
	_log = fopen(_data.log_file, "w+");

	char msg_cmp[BUFFER_SIZE] = "";

 /**********************************************************************************/

	/* Always in execution */
	while (1) {

		//Obtain the cpu usage and memory usage of the operating system
		FILE *file_cpu = popen("top -b -n2 | grep \"Cpu(s)\"|tail -n 1 | awk '{print $2 + $4}'", "r");
		FILE *file_mem = popen("free | grep Mem | awk '{print $3/$2 * 100.0}'", "r");
		//Obtain the amount of sync attacks
		FILE *file_network = popen("netstat -n -p|grep SYN_REC | wc -l", "r");
		//Obtain the last critical error registered in syslog file
		FILE *file_critical = popen("awk '{print;}' /var/log/syslog | egrep 'CRITICAL|crit' | tail -n 1", "r");

		char buffer[BUFFER_SIZE], buffer2[BUFFER_SIZE], buffer3[BUFFER_SIZE], buffer4[BUFFER_SIZE];
		char actual_cpu[THRESHOLD_SIZE] = "", actual_mem[THRESHOLD_SIZE] = "",
								actual_net[THRESHOLD_SIZE] = "";

		/* Convert the information from disk to memory in order to make
		 * the respective operations
		 */
		while(NULL != fgets(buffer, sizeof(buffer), file_cpu)) {
		}
		while(NULL != fgets(buffer2, sizeof(buffer2), file_mem)) {
		}
		while(NULL != fgets(buffer3, sizeof(buffer3), file_network)) {
		}
		while(NULL != fgets(buffer4, sizeof(buffer4), file_critical)) {
		}

		/********************************************************************/

		/* Copy actual values in order to verify later with the last value */
		for(i = 0; i < THRESHOLD_SIZE; i++ ){
			if(buffer[i] == '.' ) break;
			else actual_cpu[i] = buffer[i];
		}

		for(i = 0; i < THRESHOLD_SIZE; i++ ){
			if(buffer2[i] == '.' ) break;
			else actual_mem[i] = buffer2[i];
		}

		for(i = 0; i < THRESHOLD_SIZE; i++ ){
			actual_net[i] = buffer3[i];
		}

		char output_usage[MAX_LENGTH] = "";
		int cpu_threshold_int, mem_threshold_int, network_threshold_int;
		int actual_cpu_int, actual_mem_int, actual_net_int;

		/* convert the numerical data in type integer */
    sscanf(_cpu, "%d", &cpu_threshold_int);
		sscanf(_mem, "%d", &mem_threshold_int);
		sscanf(_net, "%d", &network_threshold_int);
		sscanf(actual_cpu, "%d", &actual_cpu_int);
		sscanf(actual_mem, "%d", &actual_mem_int);
		sscanf(actual_net, "%d", &actual_net_int);

		//Verifications of the actual CPU/memory/network and the threshold defined
		//in the configuration file

		if(actual_cpu_int >= cpu_threshold_int){
      strcat(output_usage, "\n[CRITICAL] ");
			strcat(output_usage, "- CPU Usage is currently ");
			strcat(output_usage, buffer);  /*****/
			strcat(output_usage, "which is over ");
			strcat(output_usage, _cpu);
			fprintf(_log, "%s \n" ,output_usage);
		}

		if(actual_mem_int >= mem_threshold_int){
          strcat(output_usage, "\n[CRITICAL] ");
					strcat(output_usage, "- Memory Usage is currently ");
					strcat(output_usage, buffer2); /*****/
					strcat(output_usage, "which is over ");
					strcat(output_usage, _mem);
					fprintf(_log, "%s \n" ,output_usage);
		}

		if(actual_net_int >= network_threshold_int){
          strcat(output_usage, "\n[CRITICAL] ");
					strcat(output_usage, "- SYN flood connections detected. Currently there are ");
					strcat(output_usage, buffer3); /*****/
					strcat(output_usage, "active SYN_RECV connections ");
					strcat(output_usage, "which is over the defined limit ");
					strcat(output_usage, _net);
					fprintf(_log, "%s \n" ,output_usage);
		}

		/* Verify if the last critical message has changed in order
		 * to show in the trackermon.log file
		 */

		if (strcmp(buffer4, msg_cmp) == 0 ) {

		} else {
			strcat(output_usage, "\n[CRITICAL] ");
			strcat(output_usage, "- System critical error has been detected: ");
			strcat(output_usage, buffer4);
			fprintf(_log, "%s \n" ,output_usage);
		}
		//msg_cmp = buffer4;
		strncpy (msg_cmp, buffer4, BUFFER_SIZE);

		fflush(_log);
		/* Wait a second before running again the loop */
		sleep(1);
	}

	fclose(_log);
	return (0);
}
