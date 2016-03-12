/*Author : Utsav Chokshi
  Version : 1.0
  Date : 12/03/2015
  Developer Chat ID : Utsav_Choskhi
  */

#include <menuet/os.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <limits.h>
#define INT_HEXSTRING_LENGTH (sizeof(int)*CHAR_BIT/4)

// Few strings constants
const char header[] = "Color Picker Application v1.1";
static char const HEXDIGITS[0x10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
char string[] = "Hex value for selected color : ";
char footer[] = "Developed by Utsav Chokshi";

// Convert an integer to hexadecimal string
char* int_to_hexstring(int value)
{
    int i;
    int len = INT_HEXSTRING_LENGTH+1;
    char* result = (char*)malloc(len*sizeof(char));
    result[INT_HEXSTRING_LENGTH] = '\0';

    for(i=INT_HEXSTRING_LENGTH-1; value; i--, value >>= 4) {
        int d  = value & 0xf;
        result[i] = HEXDIGITS[d];
    }

    for(;i>=0;i--){ result[i] = '0'; }

    return result;	
} 

// Draw matrix of buttons which is having different colors
void draw_matrix_of_buttons(int num_row_buttons, int num_col_buttons){
	
	int i = 0,j=0;
	int xsize = 20;
	int ysize = 20;
	int xcord = i*xsize;
	int ycord = 0;
	int color = i*10;
	int id = i + 3;
    
    // Prepare color table 
	int table[256] = {0};
	int red = 0, green = 0, blue = 0;
	i=0;
	for(red=0; red<=255; red+=51){
		for(green=0; green<=255; green+=51){
			for (blue = 0; blue <= 255; blue+= 51){
				table[i] = (red*256*256)+(green*256)+blue;
				i++;
			}
		}
	}
    
    // Create button and assign appropriate id anc color
	for(i=0; i<num_row_buttons; i++){
		ycord = (i+2)*ysize;	
		for(j=0; j<num_col_buttons; j++){
			id = i*num_col_buttons + j + 3;
			color = id - 3;
			xcord = (j+0.5)*xsize;
			__menuet__make_button(xcord,ycord,xsize,ysize,id,(__u32)table[color]);	
		}
	}
}

// Redrawing window when color button is pressed
void redraw_window(int id){
	// start redraw
	__menuet__window_redraw(1);
	// define&draw window
	__menuet__define_window(10,40,350,400,0x33FFFFFF,0,(__u32)header);
    // display string
    __menuet__write_text(10,10,0x80000000,string,strlen(string));
    // display color value
     int number = id-3;
     char* color = int_to_hexstring(number);
     //char* color = to_char_array(number);
    __menuet__write_text(220,10,0x80000000,color,strlen(color));
    // draw buttons
    draw_matrix_of_buttons(13,16);
    // display footer
    __menuet__write_text(10,320,0x80000000,footer,strlen(footer));
    // end redraw
    __menuet__window_redraw(2);
}

// Intial drawing of window 
void draw_window(void){

	// start redraw
	__menuet__window_redraw(1);
	// define&draw window
	__menuet__define_window(10,40,350,400,0x33FFFFFF,0,(__u32)header);
    // draw buttons
    draw_matrix_of_buttons(13,16);
    // display string
    __menuet__write_text(10,10,0x80000000,string,0);
    // display footer
    __menuet__write_text(10,320,0x80000000,footer,strlen(footer));
    // end redraw
    __menuet__window_redraw(2);
}

void main(void){
	
	//Draw default window layout
	draw_window();
	
	//Keep waiting for events indefinitely
	while(1)
	{   
		int event_value = __menuet__wait_for_event(); 
		switch (event_value)
		{ 
			//For window resize operation
		    case 1:
		    	draw_window();
				break;

			// For key press event	
			case 2:
			// ignore it
			__menuet__getkey();
			break;
		
            // Some button is pressed
		    case 3:
			{
			   int id = __menuet__get_button_id();
			   if(id==1){
			 	 //Close button is pressed, so return from application
			 	 return;
			   }
			   else{
			   	  // Redraw window accrodingly button is pressed.
			 	  redraw_window(id);
			   }
			   break;
		    }
		}
	}
}