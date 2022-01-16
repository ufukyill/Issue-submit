

module top_level(
	// Input of the base system clock, connected to Terasic 50MHz clock.
	input clock50MHz,
	// Listed ports below is utilised by data comms for the receiving and transmitting of data.
	input TXE,
	input RXF,
	output WR, 
	output RD,

	inout bit1,
	inout bit2,
	inout bit3,
	inout bit4,
	inout bit5,
	inout bit6,
	inout bit7,
	inout bit8
);


reg sendDataFlag;
reg nextDataBlockFlag;
reg encryptionFinishedFlag;
reg encryptionInputsLoadedFlag;
reg decryptionInputsLoadedFlag;

reg resetEncryptionModule;
reg resetDecryptionModule;

reg [127:0] encryptionkey;
reg [127:0] decryptionkey;
reg [127:0] encryptionDataIn;
reg [127:0] decryptionDataIn;
reg [127:0] UARTDataOut;
reg [103:0] cipherBlocksRemaining;

wire receivedKeyFlag;
wire receivedDataInFlag;
wire dataCommsObtainedSendFlag;
wire configDataFlag;
wire dataCommsObtainedNextBlockFlag;
wire dataCommsObtainedFinishedFlag;

wire [127:0] receivedDataIn;
wire [127:0] receivedKey;
wire [127:0] encryptionDataOut;
wire [127:0] decryptionDataOut;
wire [127:0] receivedConfigData;
wire dataEncryptedFlag;
wire dataDecryptedFlag;

// FSM states
reg[3:0] state;
reg[3:0] IDLE 			= 4'd0;
reg[3:0] NEXT_CYPHER_BLOCK 	= 4'd2;
reg[3:0] EXTRACT_CONFIG_DATA    = 4'd4;
reg[3:0] ENCRYPTION_IDLE	= 4'd5;
reg[3:0] DECRYPTION_IDLE	= 4'd6;
reg[3:0] FINISHED_ENCRYPTION    = 4'd8;
reg[3:0] SEND_DATA 		= 4'd9;


initial begin
	// Set the initial state to IDLE
	state = 3'd0;

	sendDataFlag = 0;
	nextDataBlockFlag = 0;
	encryptionInputsLoadedFlag = 0;
	decryptionInputsLoadedFlag = 0;
	resetEncryptionModule = 0;
	resetDecryptionModule = 0;
	encryptionFinishedFlag = 0;

	cipherBlocksRemaining = 104'd0;
	encryptionDataIn = 128'd0;
	decryptionDataIn = 128'd0;
	encryptionkey = 128'd0;
	decryptionkey = 128'd0;
	UARTDataOut = 128'd0;

end

// Instantiation of the Data communication module.
data_communication readAndWriteData(
	.clock50MHz					(clock50MHz),		 	 // Pin connection passed down from top
	.TXE						(TXE),				 // Pin connection passed down from top
	.RXF						(RXF),				 // Pin connection passed down from top
	.WR						(WR),				 // Pin connection passed down from top
	.RD						(RD),				 // Pin connection passed down from top

	.dataToSendFlag					(sendDataFlag),			// Input to data comms
	.dataOut128Bits					(UARTDataOut),			// Input to data comms
	.nextDataBlockFlag				(nextDataBlockFlag),		// Input to data comms
	.encryptionFinishedFlag				(encryptionFinishedFlag),	// Input to data comms

	.key						(receivedKey),		        // Output from data comms
	.dataIn128Bits					(receivedDataIn), 	 	// Output from data comms
	.configData128Bits				(receivedConfigData),	        // Output from data comms
	.receivedKeyFlag				(receivedKeyFlag),		// Output from data comms
	.receivedDataFlag				(receivedDataInFlag),	        // Output from data comms
	.receivedSendDataFlag				(dataCommsObtainedSendFlag),	// Output from data comms
	.receivedConfigDataFlag				(configDataFlag),		// Output from data comms
	.receivedNextBlockFlag				(dataCommsObtainedNextBlockFlag),// Output from data comms
	.receivedFinishedFlag				(dataCommsObtainedFinishedFlag), // Output from data comms

	.bit1									(bit1),				 // Pin connection passed down from top
	.bit2									(bit2),				 
	.bit3									(bit3),				
	.bit4									(bit4),				
	.bit5									(bit5),				 
	.bit6									(bit6),				 
	.bit7									(bit7),				 
	.bit8									(bit8)				 
);

// Instantiation of the AES encryption module.
encryption encryptAES(
	.inputData				(encryptionDataIn),			// Input to encryption
	.key						(encryptionkey),		// Input to encryption
	.clock					(clock50MHz),				// Input to encryption
	.inputsLoadedFlag		(encryptionInputsLoadedFlag),			// Input to encryption
	.resetModule			(resetEncryptionModule),			// Input to encryption
	.outputData				(encryptionDataOut), 			// Output from encryption
	.dataEncryptedFlag	(dataEncryptedFlag)					// Output from encryption
);

// Instantiation of the AES decryption module.
decryption decryptAES(
	.inputData				(decryptionDataIn),			// Input to decryption
	.key						(decryptionkey),		// Input to decryption
	.clock					(clock50MHz),				// Input to decryption
	.inputsLoadedFlag		(decryptionInputsLoadedFlag),			// Input to decryption
	.resetModule			(resetDecryptionModule),			// Input to decryption
	.outputData				(decryptionDataOut),			// Output from decryption
	.dataDecryptedFlag	(dataDecryptedFlag)					// Output from decryption
);


always @(posedge clock50MHz) begin
	case(state)

		// The state will constantly loop round until configDataFlag is set high in The
		// data comms module, in which case the FSM will transition to EXTRACT_CONFIG_DATA.
		IDLE: begin
			sendDataFlag = 0;
			resetEncryptionModule = 0;
			resetDecryptionModule = 0;
			if(configDataFlag == 1) begin
				state = EXTRACT_CONFIG_DATA;
			end
		end

		EXTRACT_CONFIG_DATA: begin
		  // Extract the value from configData which states how many data blocks are expected to be
			// encrypted/decrypted.
			cipherBlocksRemaining = receivedConfigData[127:24];
			// If in encryption mode, transition to ENCRYPTION_IDLE.
			if(receivedConfigData[7:0] == 8'h30) begin		// Encryption - char value 0 = hex vale 30.
				state = ENCRYPTION_IDLE;
			end
			// If in encryption mode, transition to DECRYPTION_IDLE.
			if(receivedConfigData[7:0] == 8'h31) begin		// Decryption - char value 1 = hex vale 31.
				state = DECRYPTION_IDLE;
			end
		end

		ENCRYPTION_IDLE: begin
			sendDataFlag = 0;
			// Wait untill both DataIn and Key flags are high, in which case load the receivedDataIn
			// and receivedKey to the encryption module and transition to SEND_DATA.
			if((receivedKeyFlag == 1) & (receivedDataInFlag == 1)) begin
				encryptionInputsLoadedFlag = 1;
				encryptionDataIn = receivedDataIn;
				encryptionkey = receivedKey;
				state = SEND_DATA;
			end
		end

		DECRYPTION_IDLE: begin
			sendDataFlag = 0;
			// Wait untill both DataIn and Key flags are high, in which case load the receivedDataIn
			// and receivedKey to the decryption module and transition to SEND_DATA.
			if((receivedKeyFlag == 1) & (receivedDataInFlag == 1)) begin
				decryptionInputsLoadedFlag = 1;
				decryptionDataIn = receivedDataIn;
				decryptionkey = receivedKey;
				state = SEND_DATA;
			end
		end

		SEND_DATA: begin
			// Set inputs loaded flag low and await until the either dataEncryptedFlag or dataDecryptedFlag
			// is high, indicating data has been processed and is ready to be sent back. In which case
			// set sendDataFlag and await for confirmation back.
			decryptionInputsLoadedFlag = 0;
			encryptionInputsLoadedFlag = 0;

			if(receivedConfigData[7:0] == 8'h30) begin		// Encryption - char value 0 = hex vale 30.
				if(dataEncryptedFlag == 1) begin
					sendDataFlag = 1;
					// Send encryption data to the data comms module.
					UARTDataOut = encryptionDataOut;
				end
			end

			if(receivedConfigData[7:0] == 8'h31) begin		// Decryption - char value 1 = hex vale 31.
				if(dataDecryptedFlag == 1) begin
					sendDataFlag = 1;
					// Send decryption data to the data comms module.
					UARTDataOut = decryptionDataOut;
				end
			end

			// Await until dataCommsObtainedSendFlag is high, indicating the data comms has successfully received
			// sendDataFlag and sent the processed data to the external application.
			if(dataCommsObtainedSendFlag == 1) begin
				sendDataFlag = 0;
				// Subtract 1 from the total amount of remaining cipher blocks and transition to
				// NEXT_CYPHER_BLOCK state.
				cipherBlocksRemaining = cipherBlocksRemaining - 104'd1;
				state = NEXT_CYPHER_BLOCK;
			end
		end

		NEXT_CYPHER_BLOCK: begin
			// Check the amount of data blocks remaining in cipherBlocksRemaining, if it is equal to
			// zero transition to FINISHED_ENCRYPTION, else set nextDataBlockFlag high. This indicates
			// to data comms that the top level design is awaiting the next data block, thus the data comms
			// should receive the next 16 bytes and pass it on to the top level module.
			if(cipherBlocksRemaining >= 104'd1) begin
				nextDataBlockFlag = 1;
				// Once the data comms has acknowledged the nextDataBlockFlag, transition to either ENCRYPTION_IDLE
				// or DECRYPTION_IDLE depending on configData.
				if(dataCommsObtainedNextBlockFlag == 1) begin
					nextDataBlockFlag = 0;
					if(receivedConfigData[7:0] == 8'h30) begin	// Encryption mode
						state = ENCRYPTION_IDLE;
					end
					if(receivedConfigData[7:0] == 8'h31) begin	// Decryption mode
						state = DECRYPTION_IDLE;
					end
				end
			end
			if(cipherBlocksRemaining == 104'd0) begin
				state = FINISHED_ENCRYPTION;
			end
		end

		// Once all the data blocks have been processed. Set encryptionFinishedFlag high,
		// await confirmation from data comms. Once confirmed set all used variable in then
		// module to zero and then set reset signal high for both encryption and decryption
		// module.
		FINISHED_ENCRYPTION: begin
			encryptionFinishedFlag = 1;
			if(dataCommsObtainedFinishedFlag == 1) begin
				UARTDataOut = 128'd0;
				sendDataFlag = 0;
				encryptionInputsLoadedFlag = 0;
				decryptionInputsLoadedFlag = 0;
				encryptionDataIn = 128'd0;
				decryptionDataIn = 128'd0;
				encryptionkey = 128'd0;
				decryptionkey = 128'd0;
				cipherBlocksRemaining = 104'd0;
				nextDataBlockFlag = 0;
				encryptionFinishedFlag = 0;
				resetEncryptionModule = 1;
				resetDecryptionModule = 1;
				state = IDLE;
			end
		end

		default: begin
			state = IDLE;
		end
	endcase
end

endmodule


// This is the AES encryption module. The module starts initially in IDLE and will await for the
// inputLoadedFlag to go high (indicating that both the data block and the key are loaded) in 
// which case the script will call upon all other instantiated modules for the encryption of the
// data block. Once the data has been fully processed and is thus encrypted the data block is loaded
// to the output and the dataEncryptedFlag is set high to indicate the completion of encryption.

module encryption #(
	// Default number of rounds is set to 32. This was added for future designs which would require
   // to change this parameter to 40 (if 192-bit key length used) and 48 (if 192-bit key length used).
	parameter numRounds = 32
)(
	input  [127:0] inputData,
	input  [127:0] key,
	input clock,
	input inputsLoadedFlag,
	input resetModule,
	output reg [127:0] outputData,
	output reg dataEncryptedFlag
);

// startTransition is used as a control parameter for the instantiated modules.
reg startTransition[0:39];

reg [5:0] calledModulesValue;
reg [3:0] loopCounter;


reg startKeyGenFlag;
reg keyCreatedFlag;
reg [4:0] keyGenCounter;


// FSM states
reg [3:0] state;
reg [3:0] IDLE					= 4'd0;
reg [3:0] KEY_GEN				= 4'd1;
reg [3:0] ADDROUNDKEY_INIT	= 4'd2;
reg [3:0] SUBBYTE_LOOP		= 4'd3;
reg [3:0] SHIFTROW_LOOP		= 4'd4;
reg [3:0] MIXCOLUMNS_LOOP	= 4'd5;
reg [3:0] ADDROUNDKEY_LOOP	= 4'd6;
reg [3:0] SUBBYTE_END		= 4'd7;
reg [3:0] SHIFTROW_END		= 4'd8;
reg [3:0] ADDROUNDKEY_END	= 4'd9;
reg [3:0] STOP					= 4'd10;
reg [3:0] RESET				= 4'd11;


wire [127:0] roundKey [0:10];
wire [127:0] tempData [0:39];
wire [3:0] counter [0:32];

// Counter values used for the selection of the Rcon values. Declared as such as only one type 
// variable can be incremented in the for loop, thus this was deemed the easiest method to achieve
// the required results.
assign counter[0]  = 1;
assign counter[4]  = 2;
assign counter[8]  = 3;
assign counter[12] = 4;
assign counter[16] = 5;
assign counter[20] = 6;
assign counter[24] = 7;
assign counter[28] = 8;
assign counter[32] = 9;

initial begin
	// Set the initial state to IDLE
	state = 4'd0;
	keyCreatedFlag = 0;
	calledModulesValue = 6'd0;

	startKeyGenFlag = 0;
	keyGenCounter = 5'd0;
	loopCounter = 4'd0;
	
	outputData = 128'd0;
	
	startTransition[0]  = 1'b0;
	startTransition[1]  = 1'b0;
	startTransition[2]  = 1'b0;
	startTransition[3]  = 1'b0;
	startTransition[4]  = 1'b0;
	startTransition[5]  = 1'b0;
	startTransition[6]  = 1'b0;
	startTransition[7]  = 1'b0;
	startTransition[8]  = 1'b0;
	startTransition[9]  = 1'b0;
	startTransition[10] = 1'b0;
	startTransition[11] = 1'b0;
	startTransition[12] = 1'b0;
	startTransition[13] = 1'b0;
	startTransition[14] = 1'b0;
	startTransition[15] = 1'b0;
	startTransition[16] = 1'b0;
	startTransition[17] = 1'b0;
	startTransition[18] = 1'b0;
	startTransition[19] = 1'b0;
	startTransition[20] = 1'b0;
	startTransition[21] = 1'b0;
	startTransition[22] = 1'b0;
	startTransition[23] = 1'b0;
	startTransition[24] = 1'b0;
	startTransition[25] = 1'b0;
	startTransition[26] = 1'b0;
	startTransition[27] = 1'b0;
	startTransition[28] = 1'b0;
	startTransition[29] = 1'b0;
	startTransition[30] = 1'b0;
	startTransition[31] = 1'b0;
	startTransition[32] = 1'b0;
	startTransition[33] = 1'b0;
	startTransition[34] = 1'b0;
	startTransition[35] = 1'b0;
	startTransition[36] = 1'b0;
	startTransition[37] = 1'b0;
	startTransition[38] = 1'b0;
	startTransition[39] = 1'b0;
	
end


key_creation keyGen(
	.clock				(clock),
	.startTransition	(startKeyGenFlag),
	.roundKeyInput		(key),
	.roundKeyOutput0	(roundKey[0]),
	.roundKeyOutput1	(roundKey[1]),	
	.roundKeyOutput2	(roundKey[2]),
	.roundKeyOutput3	(roundKey[3]),
	.roundKeyOutput4	(roundKey[4]),
	.roundKeyOutput5	(roundKey[5]),
	.roundKeyOutput6	(roundKey[6]),
	.roundKeyOutput7	(roundKey[7]),
	.roundKeyOutput8	(roundKey[8]),
	.roundKeyOutput9	(roundKey[9]),
	.roundKeyOutput10	(roundKey[10])
	
);


// The instantiation of 32 modules, including AddRoundKey, SubByte, ShiftRow and MiXColumn through the use
// generate. This was done in such a manner due to instabilities and inconsistencies experienced through 
// the use of 9 instantiated modules and tri-state buffers. Further elaboration on the matter is explained in 
// section 5.1.1.

genvar currentValue;
generate

	add_round_key AddRoundKeyInitRound(
		.inputData 			(inputData),
		.roundKey			(roundKey[0]),
		.startTransition	(startTransition[0]),
		.outputData  		(tempData[0])
	);

	for (currentValue = 0; currentValue <= numRounds; currentValue = currentValue + 4) begin : genVarLoopEncrypt
		sub_byte SubByte(
			.subByteInput 		(tempData[currentValue]),
			.startTransition	(startTransition[currentValue + 1]),
			.subByteOutput 	(tempData[currentValue + 1])
		);

		shift_row shiftRow(
			.inputData			(tempData[currentValue + 1]),
			.startTransition	(startTransition[currentValue + 2]),
			.outputData 		(tempData[currentValue + 2])
		);

		mix_columns #(
		.ENCRYPT 				 (1)
		) MixColumns (
			.inputData			 (tempData[currentValue + 2]),
			. startTransition	 (startTransition[currentValue + 3]),
			.outputData 		 (tempData[currentValue + 3])
		);

		add_round_key AddRoundKey(
			.inputData			(tempData[currentValue + 3]),
			.roundKey   		(roundKey[counter[currentValue]]),
			.startTransition	(startTransition[currentValue + 4]),
			.outputData			(tempData[currentValue + 4])
		);
	end

	sub_byte SubByteLastRound(
		.subByteInput 		(tempData[36]),
		.startTransition	(startTransition[37]),
		.subByteOutput 	(tempData[37])
	);

	shift_row shiftRowLastRound(
		.inputData			(tempData[37]),
		.startTransition	(startTransition[38]),
		.outputData			(tempData[38])
	);

	add_round_key AddRoundKeyLastRound(
		.inputData			(tempData[38]),
		.roundKey  			(roundKey[10]),
		.startTransition	(startTransition[39]),
		.outputData 		(tempData[39])
	);

endgenerate


always @(posedge clock) begin
	case(state)
		
		// The IDLE state will constantly loop round until either data is reset or input data has been loaded.
		// When data has been loaded, it will check if round keys have already been created in the previous 
      // cycle, if so it will transition to ADDROUNDKEY_INIT and miss the KEY_GEN state.
		IDLE: begin
			dataEncryptedFlag = 1'b0;
			if(resetModule == 1) begin
				state = RESET;
			end
			
			if(inputsLoadedFlag == 1) begin
				if(keyCreatedFlag == 0) begin
					state = KEY_GEN;
				end
				if(keyCreatedFlag == 1) begin
					state = ADDROUNDKEY_INIT;
				end
			end
		end
		
		KEY_GEN: begin
			startKeyGenFlag = 1'b1;
			if(keyGenCounter == 5'd2) begin
				keyGenCounter = 5'd0;
				startKeyGenFlag = 1'b0;
				keyCreatedFlag = 1'b1;
				state = ADDROUNDKEY_INIT;
			end
			keyGenCounter = keyGenCounter + 5'd1;
		end
		
		ADDROUNDKEY_INIT: begin
			
			startTransition[0] = 1'b1;
			calledModulesValue = calledModulesValue + 6'd1;
			state = SUBBYTE_LOOP;
		end	
		
		SUBBYTE_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;			
			calledModulesValue = calledModulesValue + 6'd1;
			startTransition[calledModulesValue] = 1'b1;	
			loopCounter = loopCounter + 4'd1;
			state = SHIFTROW_LOOP;
		end
		
		SHIFTROW_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			calledModulesValue = calledModulesValue + 6'd1;
			startTransition[calledModulesValue] = 1'b1;	
			state = MIXCOLUMNS_LOOP;	
		end
		
		MIXCOLUMNS_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			calledModulesValue = calledModulesValue + 6'd1;
			startTransition[calledModulesValue] = 1'b1;	
			state = ADDROUNDKEY_LOOP;
		end
		
		ADDROUNDKEY_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			calledModulesValue = calledModulesValue + 6'd1;
			startTransition[calledModulesValue] = 1'b1;	
			// If loopCounter is less than 9, transition to SUBEBYTE_LOOP and loop round till loopCounter is 
         // equal to 9, in which case transition to the last 3 end modules
			if(loopCounter == 4'd9) begin
				state = SUBBYTE_END;
			end else begin
				state = SUBBYTE_LOOP;
			end
		end
		
		SUBBYTE_END: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			calledModulesValue = calledModulesValue + 6'd1;
			startTransition[calledModulesValue] = 1'b1;	
			state = SHIFTROW_END;
		end
		
		SHIFTROW_END: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			calledModulesValue = calledModulesValue + 6'd1;
			startTransition[calledModulesValue] = 1'b1;	
			state = ADDROUNDKEY_END;
		end
		
		ADDROUNDKEY_END: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			calledModulesValue = calledModulesValue + 6'd1;
			startTransition[calledModulesValue] = 1'b1;	
			state = STOP;
		end
		
		// Load the output data, set dataEncryptedFlag high and reset all used variables apart from keyCreatedFlag.
      // Then transition to IDLE and await further input.
		STOP: begin
			outputData = tempData[39];
			dataEncryptedFlag = 1'b1;
			loopCounter = 4'd0;
			keyGenCounter = 5'd0;
			startTransition[39] = 1'b0;
			calledModulesValue = 6'd0;
			
			startTransition[0]  = 1'b0;
			startTransition[1]  = 1'b0;
			startTransition[2]  = 1'b0;
			startTransition[3]  = 1'b0;
			startTransition[4]  = 1'b0;
			startTransition[5]  = 1'b0;
			startTransition[6]  = 1'b0;
			startTransition[7]  = 1'b0;
			startTransition[8]  = 1'b0;
			startTransition[9]  = 1'b0;
			startTransition[10] = 1'b0;
			startTransition[11] = 1'b0;
			startTransition[12] = 1'b0;
			startTransition[13] = 1'b0;
			startTransition[14] = 1'b0;
			startTransition[15] = 1'b0;
			startTransition[16] = 1'b0;
			startTransition[17] = 1'b0;
			startTransition[18] = 1'b0;
			startTransition[19] = 1'b0;
			startTransition[20] = 1'b0;
			startTransition[21] = 1'b0;
			startTransition[32] = 1'b0;
			startTransition[33] = 1'b0;
			startTransition[34] = 1'b0;
			startTransition[35] = 1'b0;
			startTransition[36] = 1'b0;
			startTransition[37] = 1'b0;
			startTransition[38] = 1'b0;
			startTransition[39] = 1'b0;
			
			state = IDLE;
		end
		
		// Reset all variables used by the decryption module and transitions to IDLE and then await further input.
		RESET: begin
			keyCreatedFlag = 0;
			outputData = 128'd0;
			dataEncryptedFlag = 0;
			loopCounter = 4'd0;
			keyGenCounter = 5'd0;
			calledModulesValue = 6'd0;
			
			startTransition[0]  = 1'b0;
			startTransition[1]  = 1'b0;
			startTransition[2]  = 1'b0;
			startTransition[3]  = 1'b0;
			startTransition[4]  = 1'b0;
			startTransition[5]  = 1'b0;
			startTransition[6]  = 1'b0;
			startTransition[7]  = 1'b0;
			startTransition[8]  = 1'b0;
			startTransition[9]  = 1'b0;
			startTransition[10] = 1'b0;
			startTransition[11] = 1'b0;
			startTransition[12] = 1'b0;
			startTransition[13] = 1'b0;
			startTransition[14] = 1'b0;
			startTransition[15] = 1'b0;
			startTransition[16] = 1'b0;
			startTransition[17] = 1'b0;
			startTransition[18] = 1'b0;
			startTransition[19] = 1'b0;
			startTransition[20] = 1'b0;
			startTransition[21] = 1'b0;
			startTransition[32] = 1'b0;
			startTransition[33] = 1'b0;
			startTransition[34] = 1'b0;
			startTransition[35] = 1'b0;
			startTransition[36] = 1'b0;
			startTransition[37] = 1'b0;
			startTransition[38] = 1'b0;
			startTransition[39] = 1'b0;
			
			state = IDLE;
		end
		
		default: begin
			state = IDLE;
			dataEncryptedFlag = 1'b1;
			loopCounter = 4'd0;
			keyGenCounter = 5'd0;
			startTransition[39] = 1'b0;
			calledModulesValue = 6'd0;
		end
		
	endcase
end
endmodule


 // This is AES sBox module. With the change of the input byte, its
 // replaced with the lookup table value.

module s_box(
	input [7:0] sboxInput,
	output reg [7:0] sboxOutput
);

always @ (sboxInput) begin
		case(sboxInput)
			8'h00 : sboxOutput = 8'h63;
			8'h01 : sboxOutput = 8'h7c;
			8'h02 : sboxOutput = 8'h77;
			8'h03 : sboxOutput = 8'h7b;
			8'h04 : sboxOutput = 8'hf2;
			8'h05 : sboxOutput = 8'h6b;
			8'h06 : sboxOutput = 8'h6f;
			8'h07 : sboxOutput = 8'hc5;
			8'h08 : sboxOutput = 8'h30;
			8'h09 : sboxOutput = 8'h01;
			8'h0A : sboxOutput = 8'h67;
			8'h0B : sboxOutput = 8'h2b;
			8'h0C : sboxOutput = 8'hfe;
			8'h0D : sboxOutput = 8'hd7;
			8'h0E : sboxOutput = 8'hab;
			8'h0F : sboxOutput = 8'h76;
			8'h10 : sboxOutput = 8'hca;
			8'h11 : sboxOutput = 8'h82;
			8'h12 : sboxOutput = 8'hc9;
			8'h13 : sboxOutput = 8'h7d;
			8'h14 : sboxOutput = 8'hfa;
			8'h15 : sboxOutput = 8'h59;
			8'h16 : sboxOutput = 8'h47;
			8'h17 : sboxOutput = 8'hf0;
			8'h18 : sboxOutput = 8'had;
			8'h19 : sboxOutput = 8'hd4;
			8'h1A : sboxOutput = 8'ha2;
			8'h1B : sboxOutput = 8'haf;
			8'h1C : sboxOutput = 8'h9c;
			8'h1D : sboxOutput = 8'ha4;
			8'h1E : sboxOutput = 8'h72;
			8'h1F : sboxOutput = 8'hc0;
			8'h20 : sboxOutput = 8'hb7;
			8'h21 : sboxOutput = 8'hfd;
			8'h22 : sboxOutput = 8'h93;
			8'h23 : sboxOutput = 8'h26;
			8'h24 : sboxOutput = 8'h36;
			8'h25 : sboxOutput = 8'h3f;
			8'h26 : sboxOutput = 8'hf7;
			8'h27 : sboxOutput = 8'hcc;
			8'h28 : sboxOutput = 8'h34;
			8'h29 : sboxOutput = 8'ha5;
			8'h2A : sboxOutput = 8'he5;
			8'h2B : sboxOutput = 8'hf1;
			8'h2C : sboxOutput = 8'h71;
			8'h2D : sboxOutput = 8'hd8;
			8'h2E : sboxOutput = 8'h31;
			8'h2F : sboxOutput = 8'h15;
			8'h30 : sboxOutput = 8'h04;
			8'h31 : sboxOutput = 8'hc7;
			8'h32 : sboxOutput = 8'h23;
			8'h33 : sboxOutput = 8'hc3;
			8'h34 : sboxOutput = 8'h18;
			8'h35 : sboxOutput = 8'h96;
			8'h36 : sboxOutput = 8'h05;
			8'h37 : sboxOutput = 8'h9a;
			8'h38 : sboxOutput = 8'h07;
			8'h39 : sboxOutput = 8'h12;
			8'h3A : sboxOutput = 8'h80;
			8'h3B : sboxOutput = 8'he2;
			8'h3C : sboxOutput = 8'heb;
			8'h3D : sboxOutput = 8'h27;
			8'h3E : sboxOutput = 8'hb2;
			8'h3F : sboxOutput = 8'h75;
			8'h40 : sboxOutput = 8'h09;
			8'h41 : sboxOutput = 8'h83;
			8'h42 : sboxOutput = 8'h2c;
			8'h43 : sboxOutput = 8'h1a;
			8'h44 : sboxOutput = 8'h1b;
			8'h45 : sboxOutput = 8'h6e;
			8'h46 : sboxOutput = 8'h5a;
			8'h47 : sboxOutput = 8'ha0;
			8'h48 : sboxOutput = 8'h52;
			8'h49 : sboxOutput = 8'h3b;
			8'h4A : sboxOutput = 8'hd6;
			8'h4B : sboxOutput = 8'hb3;
			8'h4C : sboxOutput = 8'h29;
			8'h4D : sboxOutput = 8'he3;
			8'h4E : sboxOutput = 8'h2f;
			8'h4F : sboxOutput = 8'h84;
			8'h50 : sboxOutput = 8'h53;
			8'h51 : sboxOutput = 8'hd1;
			8'h52 : sboxOutput = 8'h00;
			8'h53 : sboxOutput = 8'hed;
			8'h54 : sboxOutput = 8'h20;
			8'h55 : sboxOutput = 8'hfc;
			8'h56 : sboxOutput = 8'hb1;
			8'h57 : sboxOutput = 8'h5b;
			8'h58 : sboxOutput = 8'h6a;
			8'h59 : sboxOutput = 8'hcb;
			8'h5A : sboxOutput = 8'hbe;
			8'h5B : sboxOutput = 8'h39;
			8'h5C : sboxOutput = 8'h4a;
			8'h5D : sboxOutput = 8'h4c;
			8'h5E : sboxOutput = 8'h58;
			8'h5F : sboxOutput = 8'hcf;
			8'h60 : sboxOutput = 8'hd0;
			8'h61 : sboxOutput = 8'hef;
			8'h62 : sboxOutput = 8'haa;
			8'h63 : sboxOutput = 8'hfb;
			8'h64 : sboxOutput = 8'h43;
			8'h65 : sboxOutput = 8'h4d;
			8'h66 : sboxOutput = 8'h33;
			8'h67 : sboxOutput = 8'h85;
			8'h68 : sboxOutput = 8'h45;
			8'h69 : sboxOutput = 8'hf9;
			8'h6A : sboxOutput = 8'h02;
			8'h6B : sboxOutput = 8'h7f;
			8'h6C : sboxOutput = 8'h50;
			8'h6D : sboxOutput = 8'h3c;
			8'h6E : sboxOutput = 8'h9f;
			8'h6F : sboxOutput = 8'ha8;
			8'h70 : sboxOutput = 8'h51;
			8'h71 : sboxOutput = 8'ha3;
			8'h72 : sboxOutput = 8'h40;
			8'h73 : sboxOutput = 8'h8f;
			8'h74 : sboxOutput = 8'h92;
			8'h75 : sboxOutput = 8'h9d;
			8'h76 : sboxOutput = 8'h38;
			8'h77 : sboxOutput = 8'hf5;
			8'h78 : sboxOutput = 8'hbc;
			8'h79 : sboxOutput = 8'hb6;
			8'h7A : sboxOutput = 8'hda;
			8'h7B : sboxOutput = 8'h21;
			8'h7C : sboxOutput = 8'h10;
			8'h7D : sboxOutput = 8'hff;
			8'h7E : sboxOutput = 8'hf3;
			8'h7F : sboxOutput = 8'hd2;
			8'h80 : sboxOutput = 8'hcd;
			8'h81 : sboxOutput = 8'h0c;
			8'h82 : sboxOutput = 8'h13;
			8'h83 : sboxOutput = 8'hec;
			8'h84 : sboxOutput = 8'h5f;
			8'h85 : sboxOutput = 8'h97;
			8'h86 : sboxOutput = 8'h44;
			8'h87 : sboxOutput = 8'h17;
			8'h88 : sboxOutput = 8'hc4;
			8'h89 : sboxOutput = 8'ha7;
			8'h8A : sboxOutput = 8'h7e;
			8'h8B : sboxOutput = 8'h3d;
			8'h8C : sboxOutput = 8'h64;
			8'h8D : sboxOutput = 8'h5d;
			8'h8E : sboxOutput = 8'h19;
			8'h8F : sboxOutput = 8'h73;
			8'h90 : sboxOutput = 8'h60;
			8'h91 : sboxOutput = 8'h81;
			8'h92 : sboxOutput = 8'h4f;
			8'h93 : sboxOutput = 8'hdc;
			8'h94 : sboxOutput = 8'h22;
			8'h95 : sboxOutput = 8'h2a;
			8'h96 : sboxOutput = 8'h90;
			8'h97 : sboxOutput = 8'h88;
			8'h98 : sboxOutput = 8'h46;
			8'h99 : sboxOutput = 8'hee;
			8'h9A : sboxOutput = 8'hb8;
			8'h9B : sboxOutput = 8'h14;
			8'h9C : sboxOutput = 8'hde;
			8'h9D : sboxOutput = 8'h5e;
			8'h9E : sboxOutput = 8'h0b;
			8'h9F : sboxOutput = 8'hdb;
			8'hA0 : sboxOutput = 8'he0;
			8'hA1 : sboxOutput = 8'h32;
			8'hA2 : sboxOutput = 8'h3a;
			8'hA3 : sboxOutput = 8'h0a;
			8'hA4 : sboxOutput = 8'h49;
			8'hA5 : sboxOutput = 8'h06;
			8'hA6 : sboxOutput = 8'h24;
			8'hA7 : sboxOutput = 8'h5c;
			8'hA8 : sboxOutput = 8'hc2;
			8'hA9 : sboxOutput = 8'hd3;
			8'hAA : sboxOutput = 8'hac;
			8'hAB : sboxOutput = 8'h62;
			8'hAC : sboxOutput = 8'h91;
			8'hAD : sboxOutput = 8'h95;
			8'hAE : sboxOutput = 8'he4;
			8'hAF : sboxOutput = 8'h79;
			8'hB0 : sboxOutput = 8'he7;
			8'hB1 : sboxOutput = 8'hc8;
			8'hB2 : sboxOutput = 8'h37;
			8'hB3 : sboxOutput = 8'h6d;
			8'hB4 : sboxOutput = 8'h8d;
			8'hB5 : sboxOutput = 8'hd5;
			8'hB6 : sboxOutput = 8'h4e;
			8'hB7 : sboxOutput = 8'ha9;
			8'hB8 : sboxOutput = 8'h6c;
			8'hB9 : sboxOutput = 8'h56;
			8'hBA : sboxOutput = 8'hf4;
			8'hBB : sboxOutput = 8'hea;
			8'hBC : sboxOutput = 8'h65;
			8'hBD : sboxOutput = 8'h7a;
			8'hBE : sboxOutput = 8'hae;
			8'hBF : sboxOutput = 8'h08;
			8'hC0 : sboxOutput = 8'hba;
			8'hC1 : sboxOutput = 8'h78;
			8'hC2 : sboxOutput = 8'h25;
			8'hC3 : sboxOutput = 8'h2e;
			8'hC4 : sboxOutput = 8'h1c;
			8'hC5 : sboxOutput = 8'ha6;
			8'hC6 : sboxOutput = 8'hb4;
			8'hC7 : sboxOutput = 8'hc6;
			8'hC8 : sboxOutput = 8'he8;
			8'hC9 : sboxOutput = 8'hdd;
			8'hCA : sboxOutput = 8'h74;
			8'hCB : sboxOutput = 8'h1f;
			8'hCC : sboxOutput = 8'h4b;
			8'hCD : sboxOutput = 8'hbd;
			8'hCE : sboxOutput = 8'h8b;
			8'hCF : sboxOutput = 8'h8a;
			8'hD0 : sboxOutput = 8'h70;
			8'hD1 : sboxOutput = 8'h3e;
			8'hD2 : sboxOutput = 8'hb5;
			8'hD3 : sboxOutput = 8'h66;
			8'hD4 : sboxOutput = 8'h48;
			8'hD5 : sboxOutput = 8'h03;
			8'hD6 : sboxOutput = 8'hf6;
			8'hD7 : sboxOutput = 8'h0e;
			8'hD8 : sboxOutput = 8'h61;
			8'hD9 : sboxOutput = 8'h35;
			8'hDA : sboxOutput = 8'h57;
			8'hDB : sboxOutput = 8'hb9;
			8'hDC : sboxOutput = 8'h86;
			8'hDD : sboxOutput = 8'hc1;
			8'hDE : sboxOutput = 8'h1d;
			8'hDF : sboxOutput = 8'h9e;
			8'hE0 : sboxOutput = 8'he1;
			8'hE1 : sboxOutput = 8'hf8;
			8'hE2 : sboxOutput = 8'h98;
			8'hE3 : sboxOutput = 8'h11;
			8'hE4 : sboxOutput = 8'h69;
			8'hE5 : sboxOutput = 8'hd9;
			8'hE6 : sboxOutput = 8'h8e;
			8'hE7 : sboxOutput = 8'h94;
			8'hE8 : sboxOutput = 8'h9b;
			8'hE9 : sboxOutput = 8'h1e;
			8'hEA : sboxOutput = 8'h87;
			8'hEB : sboxOutput = 8'he9;
			8'hEC : sboxOutput = 8'hce;
			8'hED : sboxOutput = 8'h55;
			8'hEE : sboxOutput = 8'h28;
			8'hEF : sboxOutput = 8'hdf;
			8'hF0 : sboxOutput = 8'h8c;
			8'hF1 : sboxOutput = 8'ha1;
			8'hF2 : sboxOutput = 8'h89;
			8'hF3 : sboxOutput = 8'h0d;
			8'hF4 : sboxOutput = 8'hbf;
			8'hF5 : sboxOutput = 8'he6;
			8'hF6 : sboxOutput = 8'h42;
			8'hF7 : sboxOutput = 8'h68;
			8'hF8 : sboxOutput = 8'h41;
			8'hF9 : sboxOutput = 8'h99;
			8'hFA : sboxOutput = 8'h2d;
			8'hFB : sboxOutput = 8'h0f;
			8'hFC : sboxOutput = 8'hb0;
			8'hFD : sboxOutput = 8'h54;
			8'hFE : sboxOutput = 8'hbb;
			8'hFF : sboxOutput = 8'h16;
		endcase
end
endmodule


//  At the startTransition, this module will complete the 
// MixColumn opperation.

module mix_columns #(
	parameter ENCRYPT = 1
)(
	input [127:0] inputData,
	input startTransition,
	output reg [127:0] outputData
);
reg [31 : 0] w0, w1, w2, w3;
reg [31 : 0] ws0, ws1, ws2, ws3;
always @(posedge startTransition) begin: mixColumns
	w0=inputData[127:96];
	w1=inputData[95:64];
	w2=inputData[63:32];
	w3=inputData[31:0];

	ws0 = mixword(w0);
	ws1 = mixword(w1);
	ws2 = mixword(w2);
	ws3 = mixword(w3);

	outputData={ws0,ws1,ws2,ws3};
end





//Galois field functions. Due to Nb =4 for 128bit key 
//we need to consider only gm2 and gm3


// gm2
function [7 : 0] gm2(input [7 : 0] op);
begin
  gm2 = {op[6 : 0], 1'b0} ^ (8'h1b & {8{op[7]}});
end
endfunction 

// gm3
function [7 : 0] gm3(input [7 : 0] op);
begin
  gm3 = gm2(op) ^ op;
end
endfunction 

// mixw
function [31 : 0] mixword(input [31 : 0] w);
reg [7 : 0] w0, w1, w2, w3;
reg [7 : 0] mw0, mw1, mw2, mw3;
begin
  w0 = w[31 : 24];
  w1 = w[23 : 16];
  w2 = w[15 : 08];
  w3 = w[07 : 00];

  mw0 = gm2(w0) ^ gm3(w1) ^ w2      ^ w3;
  mw1 = w0      ^ gm2(w1) ^ gm3(w2) ^ w3;
  mw2 = w0      ^ w1      ^ gm2(w2) ^ gm3(w3);
  mw3 = gm3(w0) ^ w1      ^ w2      ^ gm2(w3);

  mixword = {mw0, mw1, mw2, mw3};
end
endfunction 

endmodule


// This module creates the required 1MHz clock signal (through he use of the 50MHz clock signal)
// used by data communication.

module clock_signals(
	input clock50MHz,
	output reg clock1MHz
);

reg [11:0] counter1MHz;

initial begin 
	clock1MHz = 0;
	counter1MHz = 12'd0;
end

// A counter is used to create the 1MHz clock signal. Whilst a PLL could have been used, the 
// data communication script does not require a strict 1MHz clock signal thus this was deemed
// acceptable.
always @(posedge clock50MHz) begin 
	if(counter1MHz == 12'd25) begin
		clock1MHz <= ~clock1MHz;
		counter1MHz <= 12'd0;
	end else begin
		counter1MHz <= counter1MHz + 12'd1;
	end

end

endmodule
// This is AES SubByte module. At the posedge of startTransition, each byte
// of inputData is substituted with the lookup table of sBox.

module sub_byte(
	input  [127:0] subByteInput,
	input startTransition,
	output [127:0] subByteOutput
);

// This instantiate 16 SBox modules. This purley so that all 16 bytes
// can be substituted in parallel, thus saving time.
genvar twoBytes;
generate for(twoBytes = 0; twoBytes < 128; twoBytes = twoBytes + 8) begin: subByte
	s_box subValue(
		.sboxInput			(subByteInput[twoBytes +:8]),
		.sboxOutput			(subByteOutput[twoBytes +:8])
	);
end
endgenerate

endmodule

/*
	if(startTransition == 1) begin
		for(twoBytes = 0; twoBytes < 128; twoBytes = twoBytes + 8) begin
			subValueInput = subByteInput[twoBytes +:8];
			callModule = 1;
			subByteOutput[twoBytes +:8] = subValueOutput;
			//callModule = 0;
			//TwoBytes = subValueOutput;
		end
	end
	TwoBytesOutput = subValueOutput;
	TwoBytesInput = subValueInput;
end







*/


// This is AES ShiftRow module. On the postaive edge of startTransition, certain values
// are cyclically shifted to the right. If the inputData is aranged as a 4x4 matrix as shown on 
// the LHS, then the ouput of this module is as shown on the RHS.
//		[a00, a01, a02, a03]		 [a00, a01, a02, a03]
//		[a10, a11, a12, a13] ==> [a13, a10, a11, a12]
//		[a20, a21, a22, a23] ==> [a22, a23, a20, a21]
//		[a30, a31, a32, a33]     [a31, a32, a33, a30]

module shift_row(
	input [127:0] inputData,
	input startTransition,
	output reg [127:0] outputData
);


reg [31:0] word1,word2,word3,word4,word1shifted,word2shifted,word3shifted,word4shifted;

always @(posedge startTransition) begin 
	word1=inputData[127:96];
	word2=inputData[95:64];
	word3=inputData[63:32];
	word4=inputData[31:0];

	word1shifted={word1[31:24],word2[23:16],word3[15:8],word4[7:0]};
	word2shifted={word2[31:24],word3[23:16],word4[15:8],word1[7:0]};
	word3shifted={word3[31:24],word4[23:16],word1[15:8],word2[7:0]};
	word4shifted={word4[31:24],word1[23:16],word2[15:8],word3[7:0]};

	outputData={word1shifted,word2shifted,word3shifted,word4shifted};
end
endmodule

// This is AES KeyCreation module. On the postative edge of startTransition the
// module will create 11 round keys. Due to roundKey1 equaling roundKeyInput, and
// the duration of two clock cyles per roundKey, with IDLE taken into consideration
// it will take 21 clock cycles to complet all the roundKeys.

module key_creation #(
    parameter numKeys = 11
  )(
    input clock,
    input startTransition,
    input [127:0] roundKeyInput,

    output reg [127:0] roundKeyOutput1,
    output reg [127:0] roundKeyOutput2,
    output reg [127:0] roundKeyOutput3,
    output reg [127:0] roundKeyOutput4,
    output reg [127:0] roundKeyOutput5,
    output reg [127:0] roundKeyOutput6,
    output reg [127:0] roundKeyOutput7,
    output reg [127:0] roundKeyOutput8,
    output reg [127:0] roundKeyOutput9,
    output reg [127:0] roundKeyOutput10,
    output reg [127:0] roundKeyOutput0
  );


  reg [31:0] w[44:0];//input data seperated into words
  reg [31:0] wprime[44:0]; //"word'"s are fractions of next roundkey
  integer i;//used as "word" index and round counter
  reg [31:0]  Rcon [0:9];
  reg [127:0] tempKeys [0:10];
  reg [31:0]  my_g [0:10];//outputs of gfunction of key generation


  reg [3:0] state;
  reg [3:0] IDLE			  		= 4'd0;
  reg [3:0] START_CREATE_ROUNDKEY = 4'd1;
  reg [3:0] STOP_CREATE_ROUNDKEY  = 4'd2;
  reg [3:0] STOP					= 4'd3;

  initial
  begin

    state = 4'd0;

    roundKeyOutput1  = 128'd0;
    roundKeyOutput2  = 128'd0;
    roundKeyOutput3  = 128'd0;
    roundKeyOutput4  = 128'd0;
    roundKeyOutput5  = 128'd0;
    roundKeyOutput6  = 128'd0;
    roundKeyOutput7  = 128'd0;
    roundKeyOutput8  = 128'd0;
    roundKeyOutput9  = 128'd0;
    roundKeyOutput10 = 128'd0;
    roundKeyOutput0 = 128'd0;

    tempKeys[0]  = 128'd0;
    tempKeys[1]  = 128'd0;
    tempKeys[2]  = 128'd0;
    tempKeys[3]  = 128'd0;
    tempKeys[4]  = 128'd0;
    tempKeys[5]  = 128'd0;
    tempKeys[6]  = 128'd0;
    tempKeys[7]  = 128'd0;
    tempKeys[8]  = 128'd0;
    tempKeys[9]  = 128'd0;
    tempKeys[10] = 128'd0;
  end

  

  always @(posedge clock)
  begin
    case(state)
      IDLE:
      begin
        if (startTransition==1)
        begin
          tempKeys[0]=roundKeyInput;
          roundKeyOutput0=roundKeyInput;
          state = START_CREATE_ROUNDKEY;
        end

      end
      START_CREATE_ROUNDKEY:
      begin
        

        for ( i=0 ;i<10 ;i=i+1 )
        begin

          w[4*i]  =tempKeys[i][127:96];
          w[4*i+1]=tempKeys[i][95:64];
          w[4*i+2]=tempKeys[i][63:32];
          w[4*i+3]=tempKeys[i][31:0];

		      my_g[i] = gfunc(w[4*i+3],i);


          wprime[4*i]  =w[4*i]        ^ my_g[i];
          wprime[4*i+1]=wprime[4*i]   ^ w[4*i+1];
          wprime[4*i+2]=wprime[4*i+1] ^ w[4*i+2];
          wprime[4*i+3]=wprime[4*i+2] ^ w[4*i+3];

          tempKeys[i+1]={wprime[4*i],wprime[4*i+1],wprime[4*i+2],wprime[4*i+3]};

        end
        state = STOP_CREATE_ROUNDKEY;
      end
      STOP_CREATE_ROUNDKEY:
      begin
        roundKeyOutput1=tempKeys[1];
        roundKeyOutput2=tempKeys[2];
        roundKeyOutput3=tempKeys[3];
        roundKeyOutput4=tempKeys[4];
        roundKeyOutput5=tempKeys[5];
        roundKeyOutput6=tempKeys[6];
        roundKeyOutput7=tempKeys[7];
        roundKeyOutput8=tempKeys[8];
        roundKeyOutput9=tempKeys[9];
        roundKeyOutput10=tempKeys[10];

        state =STOP;
      end
      STOP:
      begin
        
        i=0;
        
        state= IDLE;
      end

    endcase
  end

// g function of key generation
  function [31:0] gfunc(input [31:0] datain,input integer roundCounter);

    reg [7:0] sword[0:3];
    reg [31:0] shiftedonce;
    reg [7:0] Rcon [0:9];
	  reg [7:0] my_sbox;
    begin
      Rcon[0] = 8'h01;
      Rcon[1] = 8'h02;
      Rcon[2] = 8'h04;
      Rcon[3] = 8'h08;
      Rcon[4] = 8'h10;
      Rcon[5] = 8'h20;
      Rcon[6] = 8'h40;
      Rcon[7] = 8'h80;
      Rcon[8] = 8'h1b;
      Rcon[9] = 8'h36;
      shiftedonce={datain[23:0],datain[31:24]};

      my_sbox = sboxOutput(shiftedonce[31:24]);

      sword[0]= Rcon[roundCounter] ^ my_sbox;
      sword[1]=sboxOutput(shiftedonce[23:16]);
      sword[2]=sboxOutput(shiftedonce[15:8] );
      sword[3]=sboxOutput(shiftedonce[7:0]  );

      gfunc={sword[0],sword[1],sword[2],sword[3]};
    end

  endfunction

  //sbox function of gfunction
  function [7:0] sboxOutput(input [7:0] sboxInput);
  	begin

    case(sboxInput)
      8'h00 :
        sboxOutput = 8'h63;
      8'h01 :
        sboxOutput = 8'h7c;
      8'h02 :
        sboxOutput = 8'h77;
      8'h03 :
        sboxOutput = 8'h7b;
      8'h04 :
        sboxOutput = 8'hf2;
      8'h05 :
        sboxOutput = 8'h6b;
      8'h06 :
        sboxOutput = 8'h6f;
      8'h07 :
        sboxOutput = 8'hc5;
      8'h08 :
        sboxOutput = 8'h30;
      8'h09 :
        sboxOutput = 8'h01;
      8'h0A :
        sboxOutput = 8'h67;
      8'h0B :
        sboxOutput = 8'h2b;
      8'h0C :
        sboxOutput = 8'hfe;
      8'h0D :
        sboxOutput = 8'hd7;
      8'h0E :
        sboxOutput = 8'hab;
      8'h0F :
        sboxOutput = 8'h76;
      8'h10 :
        sboxOutput = 8'hca;
      8'h11 :
        sboxOutput = 8'h82;
      8'h12 :
        sboxOutput = 8'hc9;
      8'h13 :
        sboxOutput = 8'h7d;
      8'h14 :
        sboxOutput = 8'hfa;
      8'h15 :
        sboxOutput = 8'h59;
      8'h16 :
        sboxOutput = 8'h47;
      8'h17 :
        sboxOutput = 8'hf0;
      8'h18 :
        sboxOutput = 8'had;
      8'h19 :
        sboxOutput = 8'hd4;
      8'h1A :
        sboxOutput = 8'ha2;
      8'h1B :
        sboxOutput = 8'haf;
      8'h1C :
        sboxOutput = 8'h9c;
      8'h1D :
        sboxOutput = 8'ha4;
      8'h1E :
        sboxOutput = 8'h72;
      8'h1F :
        sboxOutput = 8'hc0;
      8'h20 :
        sboxOutput = 8'hb7;
      8'h21 :
        sboxOutput = 8'hfd;
      8'h22 :
        sboxOutput = 8'h93;
      8'h23 :
        sboxOutput = 8'h26;
      8'h24 :
        sboxOutput = 8'h36;
      8'h25 :
        sboxOutput = 8'h3f;
      8'h26 :
        sboxOutput = 8'hf7;
      8'h27 :
        sboxOutput = 8'hcc;
      8'h28 :
        sboxOutput = 8'h34;
      8'h29 :
        sboxOutput = 8'ha5;
      8'h2A :
        sboxOutput = 8'he5;
      8'h2B :
        sboxOutput = 8'hf1;
      8'h2C :
        sboxOutput = 8'h71;
      8'h2D :
        sboxOutput = 8'hd8;
      8'h2E :
        sboxOutput = 8'h31;
      8'h2F :
        sboxOutput = 8'h15;
      8'h30 :
        sboxOutput = 8'h04;
      8'h31 :
        sboxOutput = 8'hc7;
      8'h32 :
        sboxOutput = 8'h23;
      8'h33 :
        sboxOutput = 8'hc3;
      8'h34 :
        sboxOutput = 8'h18;
      8'h35 :
        sboxOutput = 8'h96;
      8'h36 :
        sboxOutput = 8'h05;
      8'h37 :
        sboxOutput = 8'h9a;
      8'h38 :
        sboxOutput = 8'h07;
      8'h39 :
        sboxOutput = 8'h12;
      8'h3A :
        sboxOutput = 8'h80;
      8'h3B :
        sboxOutput = 8'he2;
      8'h3C :
        sboxOutput = 8'heb;
      8'h3D :
        sboxOutput = 8'h27;
      8'h3E :
        sboxOutput = 8'hb2;
      8'h3F :
        sboxOutput = 8'h75;
      8'h40 :
        sboxOutput = 8'h09;
      8'h41 :
        sboxOutput = 8'h83;
      8'h42 :
        sboxOutput = 8'h2c;
      8'h43 :
        sboxOutput = 8'h1a;
      8'h44 :
        sboxOutput = 8'h1b;
      8'h45 :
        sboxOutput = 8'h6e;
      8'h46 :
        sboxOutput = 8'h5a;
      8'h47 :
        sboxOutput = 8'ha0;
      8'h48 :
        sboxOutput = 8'h52;
      8'h49 :
        sboxOutput = 8'h3b;
      8'h4A :
        sboxOutput = 8'hd6;
      8'h4B :
        sboxOutput = 8'hb3;
      8'h4C :
        sboxOutput = 8'h29;
      8'h4D :
        sboxOutput = 8'he3;
      8'h4E :
        sboxOutput = 8'h2f;
      8'h4F :
        sboxOutput = 8'h84;
      8'h50 :
        sboxOutput = 8'h53;
      8'h51 :
        sboxOutput = 8'hd1;
      8'h52 :
        sboxOutput = 8'h00;
      8'h53 :
        sboxOutput = 8'hed;
      8'h54 :
        sboxOutput = 8'h20;
      8'h55 :
        sboxOutput = 8'hfc;
      8'h56 :
        sboxOutput = 8'hb1;
      8'h57 :
        sboxOutput = 8'h5b;
      8'h58 :
        sboxOutput = 8'h6a;
      8'h59 :
        sboxOutput = 8'hcb;
      8'h5A :
        sboxOutput = 8'hbe;
      8'h5B :
        sboxOutput = 8'h39;
      8'h5C :
        sboxOutput = 8'h4a;
      8'h5D :
        sboxOutput = 8'h4c;
      8'h5E :
        sboxOutput = 8'h58;
      8'h5F :
        sboxOutput = 8'hcf;
      8'h60 :
        sboxOutput = 8'hd0;
      8'h61 :
        sboxOutput = 8'hef;
      8'h62 :
        sboxOutput = 8'haa;
      8'h63 :
        sboxOutput = 8'hfb;
      8'h64 :
        sboxOutput = 8'h43;
      8'h65 :
        sboxOutput = 8'h4d;
      8'h66 :
        sboxOutput = 8'h33;
      8'h67 :
        sboxOutput = 8'h85;
      8'h68 :
        sboxOutput = 8'h45;
      8'h69 :
        sboxOutput = 8'hf9;
      8'h6A :
        sboxOutput = 8'h02;
      8'h6B :
        sboxOutput = 8'h7f;
      8'h6C :
        sboxOutput = 8'h50;
      8'h6D :
        sboxOutput = 8'h3c;
      8'h6E :
        sboxOutput = 8'h9f;
      8'h6F :
        sboxOutput = 8'ha8;
      8'h70 :
        sboxOutput = 8'h51;
      8'h71 :
        sboxOutput = 8'ha3;
      8'h72 :
        sboxOutput = 8'h40;
      8'h73 :
        sboxOutput = 8'h8f;
      8'h74 :
        sboxOutput = 8'h92;
      8'h75 :
        sboxOutput = 8'h9d;
      8'h76 :
        sboxOutput = 8'h38;
      8'h77 :
        sboxOutput = 8'hf5;
      8'h78 :
        sboxOutput = 8'hbc;
      8'h79 :
        sboxOutput = 8'hb6;
      8'h7A :
        sboxOutput = 8'hda;
      8'h7B :
        sboxOutput = 8'h21;
      8'h7C :
        sboxOutput = 8'h10;
      8'h7D :
        sboxOutput = 8'hff;
      8'h7E :
        sboxOutput = 8'hf3;
      8'h7F :
        sboxOutput = 8'hd2;
      8'h80 :
        sboxOutput = 8'hcd;
      8'h81 :
        sboxOutput = 8'h0c;
      8'h82 :
        sboxOutput = 8'h13;
      8'h83 :
        sboxOutput = 8'hec;
      8'h84 :
        sboxOutput = 8'h5f;
      8'h85 :
        sboxOutput = 8'h97;
      8'h86 :
        sboxOutput = 8'h44;
      8'h87 :
        sboxOutput = 8'h17;
      8'h88 :
        sboxOutput = 8'hc4;
      8'h89 :
        sboxOutput = 8'ha7;
      8'h8A :
        sboxOutput = 8'h7e;
      8'h8B :
        sboxOutput = 8'h3d;
      8'h8C :
        sboxOutput = 8'h64;
      8'h8D :
        sboxOutput = 8'h5d;
      8'h8E :
        sboxOutput = 8'h19;
      8'h8F :
        sboxOutput = 8'h73;
      8'h90 :
        sboxOutput = 8'h60;
      8'h91 :
        sboxOutput = 8'h81;
      8'h92 :
        sboxOutput = 8'h4f;
      8'h93 :
        sboxOutput = 8'hdc;
      8'h94 :
        sboxOutput = 8'h22;
      8'h95 :
        sboxOutput = 8'h2a;
      8'h96 :
        sboxOutput = 8'h90;
      8'h97 :
        sboxOutput = 8'h88;
      8'h98 :
        sboxOutput = 8'h46;
      8'h99 :
        sboxOutput = 8'hee;
      8'h9A :
        sboxOutput = 8'hb8;
      8'h9B :
        sboxOutput = 8'h14;
      8'h9C :
        sboxOutput = 8'hde;
      8'h9D :
        sboxOutput = 8'h5e;
      8'h9E :
        sboxOutput = 8'h0b;
      8'h9F :
        sboxOutput = 8'hdb;
      8'hA0 :
        sboxOutput = 8'he0;
      8'hA1 :
        sboxOutput = 8'h32;
      8'hA2 :
        sboxOutput = 8'h3a;
      8'hA3 :
        sboxOutput = 8'h0a;
      8'hA4 :
        sboxOutput = 8'h49;
      8'hA5 :
        sboxOutput = 8'h06;
      8'hA6 :
        sboxOutput = 8'h24;
      8'hA7 :
        sboxOutput = 8'h5c;
      8'hA8 :
        sboxOutput = 8'hc2;
      8'hA9 :
        sboxOutput = 8'hd3;
      8'hAA :
        sboxOutput = 8'hac;
      8'hAB :
        sboxOutput = 8'h62;
      8'hAC :
        sboxOutput = 8'h91;
      8'hAD :
        sboxOutput = 8'h95;
      8'hAE :
        sboxOutput = 8'he4;
      8'hAF :
        sboxOutput = 8'h79;
      8'hB0 :
        sboxOutput = 8'he7;
      8'hB1 :
        sboxOutput = 8'hc8;
      8'hB2 :
        sboxOutput = 8'h37;
      8'hB3 :
        sboxOutput = 8'h6d;
      8'hB4 :
        sboxOutput = 8'h8d;
      8'hB5 :
        sboxOutput = 8'hd5;
      8'hB6 :
        sboxOutput = 8'h4e;
      8'hB7 :
        sboxOutput = 8'ha9;
      8'hB8 :
        sboxOutput = 8'h6c;
      8'hB9 :
        sboxOutput = 8'h56;
      8'hBA :
        sboxOutput = 8'hf4;
      8'hBB :
        sboxOutput = 8'hea;
      8'hBC :
        sboxOutput = 8'h65;
      8'hBD :
        sboxOutput = 8'h7a;
      8'hBE :
        sboxOutput = 8'hae;
      8'hBF :
        sboxOutput = 8'h08;
      8'hC0 :
        sboxOutput = 8'hba;
      8'hC1 :
        sboxOutput = 8'h78;
      8'hC2 :
        sboxOutput = 8'h25;
      8'hC3 :
        sboxOutput = 8'h2e;
      8'hC4 :
        sboxOutput = 8'h1c;
      8'hC5 :
        sboxOutput = 8'ha6;
      8'hC6 :
        sboxOutput = 8'hb4;
      8'hC7 :
        sboxOutput = 8'hc6;
      8'hC8 :
        sboxOutput = 8'he8;
      8'hC9 :
        sboxOutput = 8'hdd;
      8'hCA :
        sboxOutput = 8'h74;
      8'hCB :
        sboxOutput = 8'h1f;
      8'hCC :
        sboxOutput = 8'h4b;
      8'hCD :
        sboxOutput = 8'hbd;
      8'hCE :
        sboxOutput = 8'h8b;
      8'hCF :
        sboxOutput = 8'h8a;
      8'hD0 :
        sboxOutput = 8'h70;
      8'hD1 :
        sboxOutput = 8'h3e;
      8'hD2 :
        sboxOutput = 8'hb5;
      8'hD3 :
        sboxOutput = 8'h66;
      8'hD4 :
        sboxOutput = 8'h48;
      8'hD5 :
        sboxOutput = 8'h03;
      8'hD6 :
        sboxOutput = 8'hf6;
      8'hD7 :
        sboxOutput = 8'h0e;
      8'hD8 :
        sboxOutput = 8'h61;
      8'hD9 :
        sboxOutput = 8'h35;
      8'hDA :
        sboxOutput = 8'h57;
      8'hDB :
        sboxOutput = 8'hb9;
      8'hDC :
        sboxOutput = 8'h86;
      8'hDD :
        sboxOutput = 8'hc1;
      8'hDE :
        sboxOutput = 8'h1d;
      8'hDF :
        sboxOutput = 8'h9e;
      8'hE0 :
        sboxOutput = 8'he1;
      8'hE1 :
        sboxOutput = 8'hf8;
      8'hE2 :
        sboxOutput = 8'h98;
      8'hE3 :
        sboxOutput = 8'h11;
      8'hE4 :
        sboxOutput = 8'h69;
      8'hE5 :
        sboxOutput = 8'hd9;
      8'hE6 :
        sboxOutput = 8'h8e;
      8'hE7 :
        sboxOutput = 8'h94;
      8'hE8 :
        sboxOutput = 8'h9b;
      8'hE9 :
        sboxOutput = 8'h1e;
      8'hEA :
        sboxOutput = 8'h87;
      8'hEB :
        sboxOutput = 8'he9;
      8'hEC :
        sboxOutput = 8'hce;
      8'hED :
        sboxOutput = 8'h55;
      8'hEE :
        sboxOutput = 8'h28;
      8'hEF :
        sboxOutput = 8'hdf;
      8'hF0 :
        sboxOutput = 8'h8c;
      8'hF1 :
        sboxOutput = 8'ha1;
      8'hF2 :
        sboxOutput = 8'h89;
      8'hF3 :
        sboxOutput = 8'h0d;
      8'hF4 :
        sboxOutput = 8'hbf;
      8'hF5 :
        sboxOutput = 8'he6;
      8'hF6 :
        sboxOutput = 8'h42;
      8'hF7 :
        sboxOutput = 8'h68;
      8'hF8 :
        sboxOutput = 8'h41;
      8'hF9 :
        sboxOutput = 8'h99;
      8'hFA :
        sboxOutput = 8'h2d;
      8'hFB :
        sboxOutput = 8'h0f;
      8'hFC :
        sboxOutput = 8'hb0;
      8'hFD :
        sboxOutput = 8'h54;
      8'hFE :
        sboxOutput = 8'hbb;
      8'hFF :
        sboxOutput = 8'h16;
    endcase
	
	end	
  endfunction

endmodule

// This is the data communication module. Data is received and transmitted through the 
// use of this module, with the acquired and sent data coming from the top-level module.

module data_communication(
	input clock50MHz,

	input TXE,
	input RXF,
	output WR,
	output RD,

	input [127:0] dataOut128Bits,
	input dataToSendFlag,
	input nextDataBlockFlag,
	input encryptionFinishedFlag,

	output reg [127:0] configData128Bits,
	output reg [127:0] key,
	output reg [127:0] dataIn128Bits,
	
	output reg receivedKeyFlag,
	output reg receivedDataFlag,
	output reg receivedConfigDataFlag,
	output reg receivedSendDataFlag,
	output reg receivedNextBlockFlag,
	output reg receivedFinishedFlag,

	inout bit1,
	inout bit2,
	inout bit3,
	inout bit4,
	inout bit5,
	inout bit6,
	inout bit7,
	inout bit8
);

reg enableOutputs;
reg enableRD;
reg enableWR;
reg everySecondByte;

reg [7:0] FIFOBuffer [0:15];
reg [7:0] FIFODataOut;
reg [4:0] inputCounter;
reg [4:0] outputCounter;
reg [3:0] state;

// FSM states
reg [3:0] IDLE 			      = 4'd0;
reg [3:0] RECEIVE_DATA	  	   = 4'd1;
reg [3:0] LOAD_DATA_TO_SEND   = 4'd2;
reg [3:0] SEND_DATA			   = 4'd3;
reg [3:0] OBTAIN_KEY		      = 4'd4;
reg [3:0] LOAD_INPUT_DATA     = 4'd5;
reg [3:0] OBTAIN_CONFIG_DATA  = 4'd6;
reg [3:0] ENCRYPTION_FINISHED = 4'd7;
reg [3:0] STOP					   = 4'd8;

wire clock1MHz;

clock_signals callClock(
	.clock50MHz	(clock50MHz),
	.clock1MHz	(clock1MHz)
);

// Tri-state buffers are used to alternate bitN from read to write. By
// setting enableOutputs to zero, bitN is of high input impedance. Once
// enableOutputs are is set high, bitN acts as an output.
assign bit1 = enableOutputs ? FIFODataOut[0] : 1'bz;
assign bit2 = enableOutputs ? FIFODataOut[1] : 1'bz;
assign bit3 = enableOutputs ? FIFODataOut[2] : 1'bz;
assign bit4 = enableOutputs ? FIFODataOut[3] : 1'bz;
assign bit5 = enableOutputs ? FIFODataOut[4] : 1'bz;
assign bit6 = enableOutputs ? FIFODataOut[5] : 1'bz;
assign bit7 = enableOutputs ? FIFODataOut[6] : 1'bz;
assign bit8 = enableOutputs ? FIFODataOut[7] : 1'bz;

// Tri-state buffers are used for the read (RD) and write (WR) pins. The connected
// external component, UM245R, requires a high to low line transition for the read of data,
// whilst for a write its a low to high. It is because of this why the default values of RD
// is 1 and WR is 0.
assign RD = enableRD ? clock1MHz : 1'b1;
assign WR = enableWR ? clock1MHz : 1'b0;


initial begin
	// Set the initial state to IDLE
	state = 4'd0;

	key = 128'd0;
	configData128Bits = 128'd0;
	dataIn128Bits = 128'd0;

	receivedKeyFlag = 0;
	receivedConfigDataFlag = 0;
	receivedDataFlag = 0;
	receivedSendDataFlag = 0;
	receivedNextBlockFlag = 0;
	receivedFinishedFlag = 0;

	enableRD = 0;
	enableWR = 0;
	enableOutputs = 0;

	everySecondByte = 0;
	inputCounter = 5'd0;
	outputCounter = 5'd0;
	FIFODataOut = 8'd0;

	FIFOBuffer[0]  = 8'd0;
	FIFOBuffer[1]  = 8'd0;
	FIFOBuffer[2]  = 8'd0;
	FIFOBuffer[3]  = 8'd0;
	FIFOBuffer[4]  = 8'd0;
	FIFOBuffer[5]  = 8'd0;
	FIFOBuffer[6]  = 8'd0;
	FIFOBuffer[7]  = 8'd0;
	FIFOBuffer[8]  = 8'd0;
	FIFOBuffer[9]  = 8'd0;
	FIFOBuffer[10] = 8'd0;
	FIFOBuffer[11] = 8'd0;
	FIFOBuffer[12] = 8'd0;
	FIFOBuffer[13] = 8'd0;
	FIFOBuffer[14] = 8'd0;
	FIFOBuffer[15] = 8'd0;
end


always @(posedge clock1MHz) begin
	case(state)

		IDLE: begin
			// If the UM245R device has available data (RXF is equal to zero) and receivedConfigDataFlag
			// has not already been set high, it indicates the receiving information is the 16-byte configData,
			// thus the state will transition to OBTAIN_CONFIG_DATA to acquire the and store the received data.
			if(RXF == 0) begin
				if(receivedConfigDataFlag == 0) begin
					everySecondByte = 0;
					state = OBTAIN_CONFIG_DATA;
				end
			end

			// If there's space available on the UM245R transmitter FIFO, and dataToSendFlag is set high by the
			// top-level module, data is available to be sent, thus acknowledge the request and transition to
			// LOAD_DATA_TO_SEND to send the processed data from the device.
			if((dataToSendFlag == 1) & (TXE == 0)) begin
				receivedDataFlag = 0;
				receivedNextBlockFlag = 0;
				receivedSendDataFlag = 1;
				dataIn128Bits = 128'd0;
				state = LOAD_DATA_TO_SEND;
			end

			// If there is available data to be collected in the UM245R device and the nextDataBlockFlag has been
			// set high by the top-level module, acknowledge the request and transition to RECEIVE_DATA to collect
			// the incoming 16 bytes.
			if((nextDataBlockFlag == 1) & (RXF == 0)) begin
				everySecondByte = 0;
				receivedSendDataFlag = 0;
				receivedDataFlag = 0;
				receivedNextBlockFlag = 1;
				state = RECEIVE_DATA;
			end

			// If encryptionFinishedFlag is set high by the top-level module, once again acknowledge the request and
			// transition to ENCRYPTION_FINISHED state for the reset of all stored variables used for this module.
			if(encryptionFinishedFlag == 1) begin
				receivedFinishedFlag = 1;
				receivedConfigDataFlag = 0;
				state = ENCRYPTION_FINISHED;
			end
		end

		OBTAIN_CONFIG_DATA : begin
			// If the configData has not already been received, as receivedConfigDataFlag is low,
			// transition to RECEIVE_DATA state to collect the corresponding configData.
			if(receivedConfigDataFlag == 0) begin
				state = RECEIVE_DATA;
			end

			// Once the configData is acquired, load the stored from the FIFOBuffers to the
			// corresponding byte in the configData128Bits variable, then transition to OBTAIN_KEY state.
			if(receivedConfigDataFlag == 1) begin
				configData128Bits[7:0]     = FIFOBuffer[0];
				configData128Bits[15:8]    = FIFOBuffer[1];
				configData128Bits[23:16]   = FIFOBuffer[2];
				configData128Bits[31:24]   = FIFOBuffer[3];
				configData128Bits[39:32]   = FIFOBuffer[4];
				configData128Bits[47:40]   = FIFOBuffer[5];
				configData128Bits[55:48]   = FIFOBuffer[6];
				configData128Bits[63:56]   = FIFOBuffer[7];
				configData128Bits[71:64]   = FIFOBuffer[8];
				configData128Bits[79:72]   = FIFOBuffer[9];
				configData128Bits[87:80]   = FIFOBuffer[10];
				configData128Bits[95:88]   = FIFOBuffer[11];
				configData128Bits[103:96]  = FIFOBuffer[12];
				configData128Bits[111:104] = FIFOBuffer[13];
				configData128Bits[119:112] = FIFOBuffer[14];
				configData128Bits[127:120] = FIFOBuffer[15];

				FIFOBuffer[0]  = 8'd0;
				FIFOBuffer[1]  = 8'd0;
				FIFOBuffer[2]  = 8'd0;
				FIFOBuffer[3]  = 8'd0;
				FIFOBuffer[4]  = 8'd0;
				FIFOBuffer[5]  = 8'd0;
				FIFOBuffer[6]  = 8'd0;
				FIFOBuffer[7]  = 8'd0;
				FIFOBuffer[8]  = 8'd0;
				FIFOBuffer[9]  = 8'd0;
				FIFOBuffer[10] = 8'd0;
				FIFOBuffer[11] = 8'd0;
				FIFOBuffer[12] = 8'd0;
				FIFOBuffer[13] = 8'd0;
				FIFOBuffer[14] = 8'd0;
				FIFOBuffer[15] = 8'd0;

				state = OBTAIN_KEY;
			end
		end

		OBTAIN_KEY: begin
			// If the keyData has not already been received, as receivedKeyFlag is low,
			// transition to RECEIVE_DATA state to collect the corresponding keyData.
			if(receivedKeyFlag == 0) begin
				state = RECEIVE_DATA;
			end

			// Once the keyData is acquired, load the stored from the FIFOBuffers to the
			// corresponding byte in the key variable, then transition to RECEIVE_DATA state.
			if(receivedKeyFlag == 1) begin
				key[7:0]     = FIFOBuffer[0];
				key[15:8]    = FIFOBuffer[1];
				key[23:16]   = FIFOBuffer[2];
				key[31:24]   = FIFOBuffer[3];
				key[39:32]   = FIFOBuffer[4];
				key[47:40]   = FIFOBuffer[5];
				key[55:48]   = FIFOBuffer[6];
				key[63:56]   = FIFOBuffer[7];
				key[71:64]   = FIFOBuffer[8];
				key[79:72]   = FIFOBuffer[9];
				key[87:80]   = FIFOBuffer[10];
				key[95:88]   = FIFOBuffer[11];
				key[103:96]  = FIFOBuffer[12];
				key[111:104] = FIFOBuffer[13];
				key[119:112] = FIFOBuffer[14];
				key[127:120] = FIFOBuffer[15];

				FIFOBuffer[0]  = 8'd0;
				FIFOBuffer[1]  = 8'd0;
				FIFOBuffer[2]  = 8'd0;
				FIFOBuffer[3]  = 8'd0;
				FIFOBuffer[4]  = 8'd0;
				FIFOBuffer[5]  = 8'd0;
				FIFOBuffer[6]  = 8'd0;
				FIFOBuffer[7]  = 8'd0;
				FIFOBuffer[8]  = 8'd0;
				FIFOBuffer[9]  = 8'd0;
				FIFOBuffer[10] = 8'd0;
				FIFOBuffer[11] = 8'd0;
				FIFOBuffer[12] = 8'd0;
				FIFOBuffer[13] = 8'd0;
				FIFOBuffer[14] = 8'd0;
				FIFOBuffer[15] = 8'd0;

				state = RECEIVE_DATA;
			end
		end

		RECEIVE_DATA: begin
			if(RXF == 0) begin
			// If data is aviable to be collected from the UM245R device, enable the connection of RD to
			// the 1MHz clock, for the collection of data. The state will loop round until all 16 bytes have been received.
				enableRD = 1;

				// It takes one clock cycle for the UM245R to acknowledge the read requirement, thus the if statement
				// loads the 8 bits to the corresponding FIFOBuffer value, everySecondByte value. This is so due to the
				// first byte being useless as the UM245R has not had enough time to respond for the loading of a single
				// byte. The reason why this is required is because the FPGA receives a single byte at a time not a stream
				// of 16 bytes in one single go.
				if((everySecondByte == 1) & (inputCounter <= 5'd15)) begin

					// Load the values of the 8 bits (a byte) to the corresponding FIFOBuffer value.
					FIFOBuffer[inputCounter] = {bit8, bit7, bit6, bit5, bit4, bit3, bit2, bit1};

					// Increment inputCounter and check if the value is equal to 16, indicating all the 128 bit has been received.
					// Once equal to 16 set enableRD low, thus setting RD pin high through its default value in the tri-state
					// buffer declaration.
					inputCounter = inputCounter + 5'd1;
					if(inputCounter == 5'd16) begin
						inputCounter = 5'd0;
						enableRD = 0;
						// The format of the sent data from the external user application will first be the configData, then
						// the key and followed lastly by the data block. The configData and key have to be only sent once,
						// then after that all received to FSM can only be data blocks, this is so until the module is reset.

						// With the received 16-byte data, if the receivedKeyFlag and receivedConfigDataFlag are high, both were
						// already acquired thus the received data is a data block and the state will transition to LOAD_INPUT_DATA
						// to load the acquired data.
						if((receivedKeyFlag == 1) & (receivedConfigDataFlag == 1)) begin
							state = LOAD_INPUT_DATA;
						end

						// If receivedConfigDataFlag is high but receivedKeyFlag is low, the data is key of the cypher, thus the
						// FSM will transition to OBTAIN_KEY to load the key value from the FIFOBuffers to the variable. The
						// receivedKeyFlag is set high so that for the next time data is received, it has to be a data block for
						// the cypher.
						if((receivedKeyFlag == 0) & (receivedConfigDataFlag == 1)) begin
							receivedKeyFlag = 1;
							state = OBTAIN_KEY;
						end

						// If receivedConfigDataFlag is low, the received data is the configData, thus transition to
						// OBTAIN_CONFIG_DATA to load the FIFOBuffers to the corresponding data variable.
						if(receivedConfigDataFlag == 0) begin
							receivedConfigDataFlag = 1;
							state = OBTAIN_CONFIG_DATA;
						end
					end
				end
				// Togle everySecondByte every clock cycle;
				everySecondByte =~ everySecondByte;
			end
			// If no data is available in UM245R set RD high.
			if(RXF == 1) begin
				enableRD = 0;
			end
		end

		LOAD_INPUT_DATA: begin
				// Load the input received data from the FIFOBuffer to dataIn128Bits and then clear all values
				// in FIFOBuffers.
				dataIn128Bits[7:0]     = FIFOBuffer[0];
				dataIn128Bits[15:8]    = FIFOBuffer[1];
				dataIn128Bits[23:16]   = FIFOBuffer[2];
				dataIn128Bits[31:24]   = FIFOBuffer[3];
				dataIn128Bits[39:32]   = FIFOBuffer[4];
				dataIn128Bits[47:40]   = FIFOBuffer[5];
				dataIn128Bits[55:48]   = FIFOBuffer[6];
				dataIn128Bits[63:56]   = FIFOBuffer[7];
				dataIn128Bits[71:64]   = FIFOBuffer[8];
				dataIn128Bits[79:72]   = FIFOBuffer[9];
				dataIn128Bits[87:80]   = FIFOBuffer[10];
				dataIn128Bits[95:88]   = FIFOBuffer[11];
				dataIn128Bits[103:96]  = FIFOBuffer[12];
				dataIn128Bits[111:104] = FIFOBuffer[13];
				dataIn128Bits[119:112] = FIFOBuffer[14];
				dataIn128Bits[127:120] = FIFOBuffer[15];

				FIFOBuffer[0]  = 8'd0;
				FIFOBuffer[1]  = 8'd0;
				FIFOBuffer[2]  = 8'd0;
				FIFOBuffer[3]  = 8'd0;
				FIFOBuffer[4]  = 8'd0;
				FIFOBuffer[5]  = 8'd0;
				FIFOBuffer[6]  = 8'd0;
				FIFOBuffer[7]  = 8'd0;
				FIFOBuffer[8]  = 8'd0;
				FIFOBuffer[9]  = 8'd0;
				FIFOBuffer[10] = 8'd0;
				FIFOBuffer[11] = 8'd0;
				FIFOBuffer[12] = 8'd0;
				FIFOBuffer[13] = 8'd0;
				FIFOBuffer[14] = 8'd0;
				FIFOBuffer[15] = 8'd0;

				// Set receivedDataFlag, so that the top-level module knows data can now be processed by the
				// AES cypher. Once set, transition to IDLE and await further input.
				receivedDataFlag = 1;
				state = IDLE;
		end

		LOAD_DATA_TO_SEND : begin
			// Load the processed value from dataOut128Bits to the FIFOBuffers and then transition to SEND_DATA so that
			// the data could be transmitted from the FPGA.
			FIFOBuffer[0]  = dataOut128Bits[7:0];
			FIFOBuffer[1]  = dataOut128Bits[15:8];
			FIFOBuffer[2]  = dataOut128Bits[23:16];
			FIFOBuffer[3]  = dataOut128Bits[31:24];
			FIFOBuffer[4]  = dataOut128Bits[39:32];
			FIFOBuffer[5]  = dataOut128Bits[47:40];
			FIFOBuffer[6]  = dataOut128Bits[55:48];
			FIFOBuffer[7]  = dataOut128Bits[63:56];
			FIFOBuffer[8]  = dataOut128Bits[71:64];
			FIFOBuffer[9]  = dataOut128Bits[79:72];
			FIFOBuffer[10] = dataOut128Bits[87:80];
			FIFOBuffer[11] = dataOut128Bits[95:88];
			FIFOBuffer[12] = dataOut128Bits[103:96];
			FIFOBuffer[13] = dataOut128Bits[111:104];
			FIFOBuffer[14] = dataOut128Bits[119:112];
			FIFOBuffer[15] = dataOut128Bits[127:120];
			state = SEND_DATA;
		end

		SEND_DATA: begin
			// Enable the bitN pins as outputs, and connect WR signal to the 1MHz clock signal
			enableWR = 1;
			enableOutputs = 1;
			// If outputCounter is less than 16, set the FIFODataOut to the corresponding FIFOBuffer value. Each individual bit
			// of FIFODataOut is extracted and set to a corresponding bitN pin for the transmission of data. When outputCounter
			// is equal to 16 disable the output pins, reset the counters and WR and RD enable pins and transition to STOP.

			// Unlike RECEIVE_DATA, SEND_DATA does not require the use of everySecondByte, due to the data that is being sent
			// (16 bytes) begin available all at the same time.
			if(outputCounter <= 5'd16) begin
				if(outputCounter == 5'd16) begin
					enableRD = 0;
					enableWR = 0;
					enableOutputs = 0;
					inputCounter = 5'd0;
					outputCounter = 5'd0;
					state = STOP;
				end
				if(outputCounter <= 5'd15) begin
					FIFODataOut = FIFOBuffer[outputCounter];
					FIFOBuffer[outputCounter] = 8'd0;
					outputCounter = outputCounter + 5'd1;
				end
			end
		end

		// Reset all enable pins and counters and transmission to IDLE.
		STOP: begin
			enableRD = 0;
			enableWR = 0;
			enableOutputs = 0;
			inputCounter = 5'd0;
			outputCounter = 5'd0;
			receivedSendDataFlag = 0;
			state = IDLE;
		end

		// Once encryptionFinishedFlag is high and the IDLE state transmission to ENCRYPTION_FINISHED, all values used by
		// the module are reset. Thus the FSM await the next configData, key and data block.
		ENCRYPTION_FINISHED: begin
			key = 128'd0;
			configData128Bits = 128'd0;
			dataIn128Bits = 128'd0;
			receivedKeyFlag = 0;
			receivedConfigDataFlag = 0;
			receivedDataFlag = 0;
			receivedSendDataFlag = 0;
			enableRD = 0;
			enableWR = 0;
			inputCounter = 5'd0;
			outputCounter = 5'd0;
			enableOutputs = 0;
			FIFODataOut = 8'd0;
			receivedNextBlockFlag = 0;
			receivedFinishedFlag = 0;

			FIFOBuffer[0]  = 8'd0;
			FIFOBuffer[1]  = 8'd0;
			FIFOBuffer[2]  = 8'd0;
			FIFOBuffer[3]  = 8'd0;
			FIFOBuffer[4]  = 8'd0;
			FIFOBuffer[5]  = 8'd0;
			FIFOBuffer[6]  = 8'd0;
			FIFOBuffer[7]  = 8'd0;
			FIFOBuffer[8]  = 8'd0;
			FIFOBuffer[9]  = 8'd0;
			FIFOBuffer[10] = 8'd0;
			FIFOBuffer[11] = 8'd0;
			FIFOBuffer[12] = 8'd0;
			FIFOBuffer[13] = 8'd0;
			FIFOBuffer[14] = 8'd0;
			FIFOBuffer[15] = 8'd0;

			state = IDLE;
		end

		default: begin
			state = IDLE;
		end

	endcase
end
endmodule


// This is the AES AddRoundKey module. At the posedge of startTransition
// the output is determined by the XOR opperation of inputData and the
// roundKey.

module add_round_key(
	input  [127:0] inputData,
	input  [127:0] roundKey,
	input startTransition,
	output reg [127:0] outputData
);

always @(posedge startTransition) begin
	outputData = inputData ^ roundKey;
end

endmodule


// This is the decryption module. In similar case as the encryption module the module starts initially 
// in IDLE and will await for the inputLoadedFlag to go high (indicating that both the data block and 
// the key are loaded) in which case the script will call upon all other instantiated modules for the 
// decryption of the data block. Once the data has been fully processed and is thus encrypted the data 
// block is loaded to the output and the dataDecryptedFlag is set high to indicate the completion of 
// decryption.

module decryption #(
	// Default number of rounds is set to 34. This was added for future designs which would require
   // to change this parameter to 44 (if 192-bit key length used) and 52 (if 192-bit key length used).
	parameter numRounds = 34
)(
	input  [127:0] inputData,
	input  [127:0] key,
	input clock,
	input inputsLoadedFlag,
	input resetModule,
	output reg [127:0] outputData,
	output reg dataDecryptedFlag
);
	
// startTransition is used as a control parameter for the instantiated modules.
reg startTransition[0:39];
	
reg startKeyGenFlag;
reg [5:0] calledModulesValue;
reg [3:0] loopCounter;
reg [4:0] keyGenCounter;
reg keyCreatedFlag;
	
// FSM states
reg [3:0] state;
reg [3:0] IDLE					= 4'd0;
reg [3:0] KEY_GEN				= 4'd1;
reg [3:0] ADDROUNDKEY_END		= 4'd2;
reg [3:0] INV_SHIFTROW_END		= 4'd3;
reg [3:0] INV_SUBBYTE_END		= 4'd4;
reg [3:0] ADDROUNDKEY_LOOP		= 4'd5;
reg [3:0] INV_MIXCOLUMNS_LOOP	= 4'd6;
reg [3:0] INV_SHIFTROW_LOOP		= 4'd7;
reg [3:0] INV_SUBBYTE_LOOP		= 4'd8;
reg [3:0] ADDROUNDKEY_INIT		= 4'd9;
reg [3:0] STOP					= 4'd10;
reg [3:0] RESET					= 4'd11;
	
wire [127:0] roundKey [0:10];
wire [127:0] tempData [0:39];
wire [3:0] counter [0:34];

// Counter values used for the selection of the Rcon(OR TO SET KEY ORDER ???) values. Declared as such as only one type 
// variable can be incremented in the for loop, thus this was deemed the easiest method to achieve
// the required results.
assign counter[2]  = 9;
assign counter[6]  = 8;
assign counter[10] = 7;
assign counter[14] = 6;
assign counter[18] = 5;
assign counter[22] = 4;
assign counter[26] = 3;
assign counter[30] = 2;
assign counter[34] = 1;

initial begin
	// Set the initial state to IDLE
	state = 4'd0;
	keyCreatedFlag = 0;
	calledModulesValue = 6'd0;
	startKeyGenFlag = 0;
	keyGenCounter = 5'd0;
	loopCounter = 4'd0;
	
	outputData = 128'd0;
	
	startTransition[0]  = 1'b0;
	startTransition[1]  = 1'b0;
	startTransition[2]  = 1'b0;
	startTransition[3]  = 1'b0;
	startTransition[4]  = 1'b0;
	startTransition[5]  = 1'b0;
	startTransition[6]  = 1'b0;
	startTransition[7]  = 1'b0;
	startTransition[8]  = 1'b0;
	startTransition[9]  = 1'b0;
	startTransition[10] = 1'b0;
	startTransition[11] = 1'b0;
	startTransition[12] = 1'b0;
	startTransition[13] = 1'b0;
	startTransition[14] = 1'b0;
	startTransition[15] = 1'b0;
	startTransition[16] = 1'b0;
	startTransition[17] = 1'b0;
	startTransition[18] = 1'b0;
	startTransition[19] = 1'b0;
	startTransition[20] = 1'b0;
	startTransition[21] = 1'b0;
	startTransition[22] = 1'b0;
	startTransition[23] = 1'b0;
	startTransition[24] = 1'b0;
	startTransition[25] = 1'b0;
	startTransition[26] = 1'b0;
	startTransition[27] = 1'b0;
	startTransition[28] = 1'b0;
	startTransition[29] = 1'b0;
	startTransition[30] = 1'b0;
	startTransition[31] = 1'b0;
	startTransition[32] = 1'b0;
	startTransition[33] = 1'b0;
	startTransition[34] = 1'b0;
	startTransition[35] = 1'b0;
	startTransition[36] = 1'b0;
	startTransition[37] = 1'b0;
	startTransition[38] = 1'b0;
	startTransition[39] = 1'b0;
end	


key_creation keyGen(
	.clock				(clock),
	.startTransition	(startKeyGenFlag),
	.roundKeyInput		(key),
	.roundKeyOutput0	(roundKey[0]),	
	.roundKeyOutput1	(roundKey[1]),
	.roundKeyOutput2	(roundKey[2]),
	.roundKeyOutput3	(roundKey[3]),
	.roundKeyOutput4	(roundKey[4]),
	.roundKeyOutput5	(roundKey[5]),
	.roundKeyOutput6	(roundKey[6]),
	.roundKeyOutput7	(roundKey[7]),
	.roundKeyOutput8	(roundKey[8]),
	.roundKeyOutput9	(roundKey[9]),
	.roundKeyOutput10	(roundKey[10])
);

// The instantiation of 34 modules, including AddRoundKey, SubByte, ShiftRow and MiXColumn through the use
// generate. This was done in such a manner due to instabilities and inconsistencies experienced through 
// the use of 9 instantiated modules and tri-state buffers. Further elaboration on the matter is explained in 
// section 5.1.1.

genvar currentValue;
generate 
	add_round_key AddRoundKeyLastRound(
		.inputData 	 		(inputData),
		.roundKey	 		(roundKey[10]),
		.startTransition	(startTransition[0]),
		.outputData  		(tempData[0])
	);
	inv_shift_row invShiftRowLastRound(
		.inputData	 		(tempData[0]),
		.startTransition	(startTransition[1]),
		.outputData 		(tempData[1])
	);
	inv_sub_byte invSSubByteLastRound(
		.inputData  		(tempData[1]), 
		.startTransition	(startTransition[2]),
		.outputData 		(tempData[2])
	);
									     //numRounds=34 BTW
	for (currentValue = 2; currentValue <= numRounds; currentValue = currentValue + 4) begin : genVarLoopDecrypt
		add_round_key InvAddRoundKey(
			.inputData			(tempData[currentValue]),
			.roundKey  			(roundKey[counter[currentValue]]), //counter : in order to use keys in reverse order
			.startTransition	(startTransition[currentValue + 1]),
			.outputData 		(tempData[currentValue + 1])
		);
		
		inv_mix_columns invmixcol(
			.inputData			(tempData[currentValue + 1]),
			.startTransition	(startTransition[currentValue + 2]),
			.outputData 		(tempData[currentValue + 2])
		);
		
		inv_shift_row invShiftRow(
			.inputData			(tempData[currentValue + 2]),
			.startTransition	(startTransition[currentValue + 3]),
			.outputData 		(tempData[currentValue + 3])
		);
		
		inv_sub_byte SubByte(
			.inputData  		(tempData[currentValue + 3]),
			.startTransition	(startTransition[currentValue + 4]),	
			.outputData 		(tempData[currentValue + 4])
		);	
	end 	
	
	add_round_key AddRoundKeyInitRound(
		.inputData			(tempData[38]),
		.roundKey   		(roundKey[0]), 
		.startTransition	(startTransition[39]),
		.outputData 		(tempData[39])
	);
endgenerate

 
always @(posedge clock) begin
	case(state)
	
		// The IDLE state will constantly loop round until either data is reset or input data has been loaded.
		// When data has been loaded, it will check if round keys have already been created in the previous 
      // cycle, if so it will transition to ADDROUNDKEY_END and miss the KEY_GEN state.
		IDLE: begin
			dataDecryptedFlag = 1'b0;
			if(resetModule == 1) begin
				state = RESET;
			end
			if(inputsLoadedFlag == 1) begin
				if(keyCreatedFlag == 0) begin
					state = KEY_GEN;
				end
				if(keyCreatedFlag == 1) begin
					state = ADDROUNDKEY_END;
				end
			end
		end
		
		KEY_GEN: begin
			startKeyGenFlag = 1'b1;
			keyGenCounter = keyGenCounter + 5'd1;
			if(keyGenCounter == 5'd22) begin //WHY DO WE NEED GENERATE KEYS 22 TIMES? 
				keyGenCounter = 5'd0;		// AND IT WORKS FOR 11 TOO.
				startKeyGenFlag = 1'b0;
				keyCreatedFlag = 1'b1;
				state = ADDROUNDKEY_END;
			end
		end
		
		ADDROUNDKEY_END: begin
			startTransition[0] = 1'b1;//start ADDROUNDKEY_END
			calledModulesValue = calledModulesValue + 6'd1;
			state = INV_SHIFTROW_END;
		end	//calledModulesValue=1
		
		INV_SHIFTROW_END: begin
			startTransition[calledModulesValue - 1] = 1'b0;//shut previous module			
			startTransition[calledModulesValue] = 1'b1;	//initiate this module's op
			calledModulesValue = calledModulesValue + 6'd1;
			state = INV_SUBBYTE_END;
		end//calledModulesValue=2
		
		INV_SUBBYTE_END: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			startTransition[calledModulesValue] = 1'b1;	
			calledModulesValue = calledModulesValue + 6'd1;
			state = ADDROUNDKEY_LOOP;	
		end //calledModulesValue=3
		
		ADDROUNDKEY_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			startTransition[calledModulesValue] = 1'b1;	
			calledModulesValue = calledModulesValue + 6'd1;
			state = INV_MIXCOLUMNS_LOOP;
			loopCounter = loopCounter + 4'd1;

		end//calledModulesValue = 3 , loopCounter = 1
		
		INV_MIXCOLUMNS_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			startTransition[calledModulesValue] = 1'b1;	
			calledModulesValue = calledModulesValue + 6'd1;
			state = INV_SHIFTROW_LOOP;
		end//calledModulesValue = 4 , loopCounter = 1
		
		INV_SHIFTROW_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			startTransition[calledModulesValue] = 1'b1;
			calledModulesValue = calledModulesValue + 6'd1;
			state = INV_SUBBYTE_LOOP;
		end//loopCounter = 1, calledModulesValue[loopCounter] = [5,10,15,20,25,30...] 
		
		INV_SUBBYTE_LOOP: begin
			startTransition[calledModulesValue - 1] = 1'b0;	
			startTransition[calledModulesValue] = 1'b1;
			calledModulesValue = calledModulesValue + 6'd1;	
			// If loopCounter is less than 9, transition to SUBEBYTE_LOOP and loop round till loopCounter is 
         	// equal to 9, in which case transition to the last 3 end modules
			if(loopCounter == 4'd9) begin
				state = ADDROUNDKEY_INIT;
			end else begin
				state = ADDROUNDKEY_LOOP;
			end
		end
		


		ADDROUNDKEY_INIT: begin //loopCounter = 9
			startTransition[calledModulesValue - 1] = 1'b0;	
			startTransition[calledModulesValue] = 1'b1;	
			calledModulesValue = calledModulesValue + 6'd1;
			state = STOP;
		end
		
		// Load the output data, set dataDecryptedFlag high and reset all used variables apart from keyCreatedFlag.
      // Then transition to IDLE and await further input.
		STOP: begin
			outputData = tempData[39];
			dataDecryptedFlag = 1'b1;
			loopCounter = 4'd0;
			keyGenCounter = 5'd0;
			startTransition[39] = 1'b0;
			calledModulesValue = 6'd0;
			
			startTransition[0]  = 1'b0;
			startTransition[1]  = 1'b0;
			startTransition[2]  = 1'b0;
			startTransition[3]  = 1'b0;
			startTransition[4]  = 1'b0;
			startTransition[5]  = 1'b0;
			startTransition[6]  = 1'b0;
			startTransition[7]  = 1'b0;
			startTransition[8]  = 1'b0;
			startTransition[9]  = 1'b0;
			startTransition[10] = 1'b0;
			startTransition[11] = 1'b0;
			startTransition[12] = 1'b0;
			startTransition[13] = 1'b0;
			startTransition[14] = 1'b0;
			startTransition[15] = 1'b0;
			startTransition[16] = 1'b0;
			startTransition[17] = 1'b0;
			startTransition[18] = 1'b0;
			startTransition[19] = 1'b0;
			startTransition[20] = 1'b0;
			startTransition[21] = 1'b0;
			startTransition[32] = 1'b0;
			startTransition[33] = 1'b0;
			startTransition[34] = 1'b0;
			startTransition[35] = 1'b0;
			startTransition[36] = 1'b0;
			startTransition[37] = 1'b0;
			startTransition[38] = 1'b0;
			startTransition[39] = 1'b0;
			state = IDLE;
		end
		
		RESET: begin
			keyCreatedFlag = 0;
			outputData = 128'd0;
			dataDecryptedFlag = 1'b0;
			loopCounter = 4'd0;
			keyGenCounter = 5'd0;
			startTransition[39] = 1'b0;
			calledModulesValue = 6'd0;
			
			startTransition[0]  = 1'b0;
			startTransition[1]  = 1'b0;
			startTransition[2]  = 1'b0;
			startTransition[3]  = 1'b0;
			startTransition[4]  = 1'b0;
			startTransition[5]  = 1'b0;
			startTransition[6]  = 1'b0;
			startTransition[7]  = 1'b0;
			startTransition[8]  = 1'b0;
			startTransition[9]  = 1'b0;
			startTransition[10] = 1'b0;
			startTransition[11] = 1'b0;
			startTransition[12] = 1'b0;
			startTransition[13] = 1'b0;
			startTransition[14] = 1'b0;
			startTransition[15] = 1'b0;
			startTransition[16] = 1'b0;
			startTransition[17] = 1'b0;
			startTransition[18] = 1'b0;
			startTransition[19] = 1'b0;
			startTransition[20] = 1'b0;
			startTransition[21] = 1'b0;
			startTransition[32] = 1'b0;
			startTransition[33] = 1'b0;
			startTransition[34] = 1'b0;
			startTransition[35] = 1'b0;
			startTransition[36] = 1'b0;
			startTransition[37] = 1'b0;
			startTransition[38] = 1'b0;
			startTransition[39] = 1'b0;
			
			state = IDLE;
		end
		default: begin
			state = IDLE;
		end
	endcase

end
endmodule

 // This is AES inverse sBox module. With the change of the input byte, its
 // replaced with the lookup table value.
 
 module inv_s_box(
	input  [7:0] inputValue,
	output reg [7:0] outputValue
);

always @(inputValue) begin 
	case(inputValue)
		8'h00 : outputValue = 8'h52;  
		8'h01 : outputValue = 8'h09;  
		8'h02 : outputValue = 8'h6a;  
		8'h03 : outputValue = 8'hd5;  
		8'h04 : outputValue = 8'h30;  
		8'h05 : outputValue = 8'h36;  
		8'h06 : outputValue = 8'ha5; 
		8'h07 : outputValue = 8'h38;  
		8'h08 : outputValue = 8'hbf;  
		8'h09 : outputValue = 8'h40;  
		8'h0a : outputValue = 8'ha3;  
		8'h0b : outputValue = 8'h9e;  
		8'h0c : outputValue = 8'h81;  
		8'h0d : outputValue = 8'hf3;  
		8'h0e : outputValue = 8'hd7;  
		8'h0f : outputValue = 8'hfb;
		8'h10 : outputValue = 8'h7c;  
		8'h11 : outputValue = 8'he3;  
		8'h12 : outputValue = 8'h39;  
		8'h13 : outputValue = 8'h82;  
		8'h14 : outputValue = 8'h9b;  
		8'h15 : outputValue = 8'h2f;  
		8'h16 : outputValue = 8'hff;  
		8'h17 : outputValue = 8'h87;  
		8'h18 : outputValue = 8'h34;  
		8'h19 : outputValue = 8'h8e;  
		8'h1a : outputValue = 8'h43;  
		8'h1b : outputValue = 8'h44;  
		8'h1c : outputValue = 8'hc4; 
		8'h1d : outputValue = 8'hde;  
		8'h1e : outputValue = 8'he9;  
		8'h1f : outputValue = 8'hcb;
		8'h20 : outputValue = 8'h54;  
		8'h21 : outputValue = 8'h7b;  
		8'h22 : outputValue = 8'h94;  
		8'h23 : outputValue = 8'h32;  
		8'h24 : outputValue = 8'ha6;  
		8'h25 : outputValue = 8'hc2;  
		8'h26 : outputValue = 8'h23;  
		8'h27 : outputValue = 8'h3d;  
		8'h28 : outputValue = 8'hee;  
		8'h29 : outputValue = 8'h4c;  
		8'h2a : outputValue = 8'h95;  
		8'h2b : outputValue = 8'h0b;  
		8'h2c : outputValue = 8'h42; 
		8'h2d : outputValue = 8'hfa;  
		8'h2e : outputValue = 8'hc3;  
		8'h2f : outputValue = 8'h4e;
		8'h30 : outputValue = 8'h08;  
		8'h31 : outputValue = 8'h2e;  
		8'h32 : outputValue = 8'ha1;  
		8'h33 : outputValue = 8'h66;  
		8'h34 : outputValue = 8'h28;  
		8'h35 : outputValue = 8'hd9;  
		8'h36 : outputValue = 8'h24;  
		8'h37 : outputValue = 8'hb2;  
		8'h38 : outputValue = 8'h76;  
		8'h39 : outputValue = 8'h5b;  
		8'h3a : outputValue = 8'ha2;  
		8'h3b : outputValue = 8'h49;  
		8'h3c : outputValue = 8'h6d;
		8'h3d : outputValue = 8'h8b;  
		8'h3e : outputValue = 8'hd1;  
		8'h3f : outputValue = 8'h25;
		8'h40 : outputValue = 8'h72;  
		8'h41 : outputValue = 8'hf8;  
		8'h42 : outputValue = 8'hf6;  
		8'h43 : outputValue = 8'h64;  
		8'h44 : outputValue = 8'h86;  
		8'h45 : outputValue = 8'h68;  
		8'h46 : outputValue = 8'h98;  
		8'h47 : outputValue = 8'h16;  
		8'h48 : outputValue = 8'hd4;  
		8'h49 : outputValue = 8'ha4;  
		8'h4a : outputValue = 8'h5c;  
		8'h4b : outputValue = 8'hcc;  
		8'h4c : outputValue = 8'h5d; 
		8'h4d : outputValue = 8'h65;  
		8'h4e : outputValue = 8'hb6;  
		8'h4f : outputValue = 8'h92;
		8'h50 : outputValue = 8'h6c;  
		8'h51 : outputValue = 8'h70;  
		8'h52 : outputValue = 8'h48;  
		8'h53 : outputValue = 8'h50;  
		8'h54 : outputValue = 8'hfd;  
		8'h55 : outputValue = 8'hed;  
		8'h56 : outputValue = 8'hb9;  
		8'h57 : outputValue = 8'hda;  
		8'h58 : outputValue = 8'h5e;  
		8'h59 : outputValue = 8'h15;  
		8'h5a : outputValue = 8'h46;  
		8'h5b : outputValue = 8'h57;  
		8'h5c : outputValue = 8'ha7; 
		8'h5d : outputValue = 8'h8d;  
		8'h5e : outputValue = 8'h9d;  
		8'h5f : outputValue = 8'h84;
		8'h60 : outputValue = 8'h90;  
		8'h61 : outputValue = 8'hd8;  
		8'h62 : outputValue = 8'hab;  
		8'h63 : outputValue = 8'h00;  
		8'h64 : outputValue = 8'h8c;  
		8'h65 : outputValue = 8'hbc;  
		8'h66 : outputValue = 8'hd3;  
		8'h67 : outputValue = 8'h0a;  
		8'h68 : outputValue = 8'hf7;  
		8'h69 : outputValue = 8'he4;  
		8'h6a : outputValue = 8'h58;  
		8'h6b : outputValue = 8'h05;  
		8'h6c : outputValue = 8'hb8; 
		8'h6d : outputValue = 8'hb3;  
		8'h6e : outputValue = 8'h45;  
		8'h6f : outputValue = 8'h06;
		8'h70 : outputValue = 8'hd0;  
		8'h71 : outputValue = 8'h2c;  
		8'h72 : outputValue = 8'h1e;  
		8'h73 : outputValue = 8'h8f;  
		8'h74 : outputValue = 8'hca;  
		8'h75 : outputValue = 8'h3f;  
		8'h76 : outputValue = 8'h0f;  
		8'h77 : outputValue = 8'h02;  
		8'h78 : outputValue = 8'hc1;  
		8'h79 : outputValue = 8'haf;  
		8'h7a : outputValue = 8'hbd;  
		8'h7b : outputValue = 8'h03;  
		8'h7c : outputValue = 8'h01; 
		8'h7d : outputValue = 8'h13;  
		8'h7e : outputValue = 8'h8a;  
		8'h7f : outputValue = 8'h6b;
		8'h80 : outputValue = 8'h3a;  
		8'h81 : outputValue = 8'h91;  
		8'h82 : outputValue = 8'h11;  
		8'h83 : outputValue = 8'h41;  
		8'h84 : outputValue = 8'h4f;  
		8'h85 : outputValue = 8'h67;  
		8'h86 : outputValue = 8'hdc;  
		8'h87 : outputValue = 8'hea;  
		8'h88 : outputValue = 8'h97;  
		8'h89 : outputValue = 8'hf2;  
		8'h8a : outputValue = 8'hcf;  
		8'h8b : outputValue = 8'hce;  
		8'h8c : outputValue = 8'hf0; 
		8'h8d : outputValue = 8'hb4;  
		8'h8e : outputValue = 8'he6;  
		8'h8f : outputValue = 8'h73;
		8'h90 : outputValue = 8'h96;  
		8'h91 : outputValue = 8'hac;  
		8'h92 : outputValue = 8'h74;  
		8'h93 : outputValue = 8'h22;  
		8'h94 : outputValue = 8'he7;  
		8'h95 : outputValue = 8'had;  
		8'h96 : outputValue = 8'h35;  
		8'h97 : outputValue = 8'h85;  
		8'h98 : outputValue = 8'he2;  
		8'h99 : outputValue = 8'hf9;  
		8'h9a : outputValue = 8'h37;  
		8'h9b : outputValue = 8'he8;  
		8'h9c : outputValue = 8'h1c; 
		8'h9d : outputValue = 8'h75;  
		8'h9e : outputValue = 8'hdf;  
		8'h9f : outputValue = 8'h6e;
		8'ha0 : outputValue = 8'h47;  
		8'ha1 : outputValue = 8'hf1;  
		8'ha2 : outputValue = 8'h1a;  
		8'ha3 : outputValue = 8'h71;  
		8'ha4 : outputValue = 8'h1d;  
		8'ha5 : outputValue = 8'h29;  
		8'ha6 : outputValue = 8'hc5;  
		8'ha7 : outputValue = 8'h89;  
		8'ha8 : outputValue = 8'h6f;  
		8'ha9 : outputValue = 8'hb7;  
		8'haa : outputValue = 8'h62;  
		8'hab : outputValue = 8'h0e;  
		8'hac : outputValue = 8'haa; 
		8'had : outputValue = 8'h18;  
		8'hae : outputValue = 8'hbe;  
		8'haf : outputValue = 8'h1b;
		8'hb0 : outputValue = 8'hfc;  
		8'hb1 : outputValue = 8'h56;  
		8'hb2 : outputValue = 8'h3e;  
		8'hb3 : outputValue = 8'h4b;  
		8'hb4 : outputValue = 8'hc6;  
		8'hb5 : outputValue = 8'hd2;  
		8'hb6 : outputValue = 8'h79;  
		8'hb7 : outputValue = 8'h20;  
		8'hb8 : outputValue = 8'h9a;  
		8'hb9 : outputValue = 8'hdb;  
		8'hba : outputValue = 8'hc0;  
		8'hbb : outputValue = 8'hfe;  
		8'hbc : outputValue = 8'h78; 
		8'hbd : outputValue = 8'hcd;  
		8'hbe : outputValue = 8'h5a;  
		8'hbf : outputValue = 8'hf4;
		8'hc0 : outputValue = 8'h1f;  
		8'hc1 : outputValue = 8'hdd;  
		8'hc2 : outputValue = 8'ha8;  
		8'hc3 : outputValue = 8'h33;  
		8'hc4 : outputValue = 8'h88;  
		8'hc5 : outputValue = 8'h07;  
		8'hc6 : outputValue = 8'hc7;  
		8'hc7 : outputValue = 8'h31;  
		8'hc8 : outputValue = 8'hb1;  
		8'hc9 : outputValue = 8'h12;  
		8'hca : outputValue = 8'h10;  
		8'hcb : outputValue = 8'h59;  
		8'hcc : outputValue = 8'h27; 
		8'hcd : outputValue = 8'h80;  
		8'hce : outputValue = 8'hec;  
		8'hcf : outputValue = 8'h5f;
		8'hd0 : outputValue = 8'h60;  
		8'hd1 : outputValue = 8'h51;  
		8'hd2 : outputValue = 8'h7f;  
		8'hd3 : outputValue = 8'ha9;  
		8'hd4 : outputValue = 8'h19;  
		8'hd5 : outputValue = 8'hb5;  
		8'hd6 : outputValue = 8'h4a;  
		8'hd7 : outputValue = 8'h0d;  
		8'hd8 : outputValue = 8'h2d;  
		8'hd9 : outputValue = 8'he5;  
		8'hda : outputValue = 8'h7a;  
		8'hdb : outputValue = 8'h9f;  
		8'hdc : outputValue = 8'h93; 
		8'hdd : outputValue = 8'hc9;  
		8'hde : outputValue = 8'h9c;  
		8'hdf : outputValue = 8'hef;
		8'he0 : outputValue = 8'ha0;  
		8'he1 : outputValue = 8'he0;  
		8'he2 : outputValue = 8'h3b;  
		8'he3 : outputValue = 8'h4d;  
		8'he4 : outputValue = 8'hae;  
		8'he5 : outputValue = 8'h2a;  
		8'he6 : outputValue = 8'hf5;  
		8'he7 : outputValue = 8'hb0;  
		8'he8 : outputValue = 8'hc8;  
		8'he9 : outputValue = 8'heb;  
		8'hea : outputValue = 8'hbb;  
		8'heb : outputValue = 8'h3c;  
		8'hec : outputValue = 8'h83; 
		8'hed : outputValue = 8'h53;  
		8'hee : outputValue = 8'h99;  
		8'hef : outputValue = 8'h61;
		8'hf0 : outputValue = 8'h17;  
		8'hf1 : outputValue = 8'h2b;  
		8'hf2 : outputValue = 8'h04;  
		8'hf3 : outputValue = 8'h7e;  
		8'hf4 : outputValue = 8'hba;  
		8'hf5 : outputValue = 8'h77;  
		8'hf6 : outputValue = 8'hd6;  
		8'hf7 : outputValue = 8'h26;  
		8'hf8 : outputValue = 8'he1;  
		8'hf9 : outputValue = 8'h69;  
		8'hfa : outputValue = 8'h14;  
		8'hfb : outputValue = 8'h63;  
		8'hfc : outputValue = 8'h55; 
		8'hfd : outputValue = 8'h21;  
		8'hfe : outputValue = 8'h0c;  
		8'hff : outputValue = 8'h7d;
	endcase
end
endmodule

module inv_mix_columns(
    input [127:0] inputData,
	input startTransition,
	output reg [127:0] outputData
);
reg [31 : 0] w0, w1, w2, w3;
reg [31 : 0] ws0, ws1, ws2, ws3;
always @(posedge startTransition) begin : inv_mix_columns
    
    w0 = inputData[127 : 096];
    w1 = inputData[095 : 064];
    w2 = inputData[063 : 032];
    w3 = inputData[031 : 000];
  
    ws0 = inv_mixw(w0);
    ws1 = inv_mixw(w1);
    ws2 = inv_mixw(w2);
    ws3 = inv_mixw(w3);
   
    outputData= {ws0, ws1, ws2, ws3};



end



 

    //INV MIXWORD FUNCTION
    function [31 : 0] inv_mixw(input [31 : 0] w);
    reg [7 : 0] b0, b1, b2, b3;
    reg [7 : 0] mb0, mb1, mb2, mb3;
    begin
    b0 = w[31 : 24];
    b1 = w[23 : 16];
    b2 = w[15 : 08];
    b3 = w[07 : 00];

    mb0 = gm14(b0) ^ gm11(b1) ^ gm13(b2) ^ gm09(b3);
    mb1 = gm09(b0) ^ gm14(b1) ^ gm11(b2) ^ gm13(b3);
    mb2 = gm13(b0) ^ gm09(b1) ^ gm14(b2) ^ gm11(b3);
    mb3 = gm11(b0) ^ gm13(b1) ^ gm09(b2) ^ gm14(b3);

    inv_mixw = {mb0, mb1, mb2, mb3};
    end
    endfunction






    //GAOLIS MULTIPLICATION FUNCTIONS 
    //FROM :https://github.com/secworks/aes/blob/master/src/rtl/aes_encipher_block.v
    function [7 : 0] gm2(input [7 : 0] op);
    begin
    gm2 = {op[6 : 0], 1'b0} ^ (8'h1b & {8{op[7]}});
    end
    endfunction // gm2

    function [7 : 0] gm3(input [7 : 0] op);
    begin
    gm3 = gm2(op) ^ op;
    end
    endfunction // gm3

    function [7 : 0] gm4(input [7 : 0] op);
    begin
    gm4 = gm2(gm2(op));
    end
    endfunction // gm4

    function [7 : 0] gm8(input [7 : 0] op);
    begin
    gm8 = gm2(gm4(op));
    end
    endfunction // gm8

    function [7 : 0] gm09(input [7 : 0] op);
    begin
    gm09 = gm8(op) ^ op;
    end
    endfunction // gm09

    function [7 : 0] gm11(input [7 : 0] op);
    begin
    gm11 = gm8(op) ^ gm2(op) ^ op;
    end
    endfunction // gm11

    function [7 : 0] gm13(input [7 : 0] op);
    begin
    gm13 = gm8(op) ^ gm4(op) ^ op;
    end
    endfunction // gm13

    function [7 : 0] gm14(input [7 : 0] op);
    begin
    gm14 = gm8(op) ^ gm4(op) ^ gm2(op);
    end
    endfunction // gm14




endmodule


// This is AES inverse ShiftRow module. On the postaive edge of startTransition, certain values
// are cyclically shifted to the left. If the inputData is aranged as a 4x4 matrix as shown on 
// the LHS, then the ouput of this module is as shown on the RHS.
//		[a00, a01, a02, a03]		 [a00, a01, a02, a03]
//		[a10, a11, a12, a13] ==> [a11, a12, a13, a10]
//		[a20, a21, a22, a23] ==> [a22, a23, a20, a21]
//		[a30, a31, a32, a33]     [a33, a30, a31, a32]

module inv_shift_row(
	input [127:0] inputData,
	input startTransition,
	output reg [127:0] outputData
);
reg [31:0] word1,word2,word3,word4,word1s,word2s,word3s,word4s;


always @(posedge startTransition) begin 

word1=inputData[127:96];
word2=inputData[95:64];
word3=inputData[63:32];
word4=inputData[31:0];

word1s={word1[31:24],word4[23:16],word3[15:8],word2[7:0]};
word2s={word2[31:24],word1[23:16],word4[15:8],word3[7:0]};
word3s={word3[31:24],word2[23:16],word1[15:8],word4[7:0]};
word4s={word4[31:24],word3[23:16],word2[15:8],word1[7:0]};


outputData={word1s,word2s,word3s,word4s};

end		  
endmodule


// This is AES inverse SubByte module. At the posedge of startTransition, each byte
// of inputData is substituted with the lookup table of inverse sBox.

module inv_sub_byte(
	input  [127:0] inputData,
	input  startTransition,
	output [127:0] outputData
);

// This instantiate 16 inverse SBox modules. This purley so that all 16 bytes 
// can be substituted in parallel, thus saving time.
genvar twoBytes;
generate for(twoBytes = 0; twoBytes < 128; twoBytes = twoBytes + 8) begin: subByte
	inv_s_box subValue(
		.inputValue	 (inputData[twoBytes +:8]),
		.outputValue (outputData[twoBytes +:8])
	);
end
endgenerate

endmodule
