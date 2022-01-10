module encryption #(
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////
module sub_byte(
	input  [127:0] subByteInput,
	input startTransition,
	output [127:0] subByteOutput
);

	genvar twoBytes;
		generate for(twoBytes = 0; twoBytes < 128; twoBytes = twoBytes + 8) begin: subByte
			s_box subValue(
				.sboxInput			(subByteInput[twoBytes +:8]),
				.sboxOutput			(subByteOutput[twoBytes +:8])
			);
		end
	endgenerate
endmodule

////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

















