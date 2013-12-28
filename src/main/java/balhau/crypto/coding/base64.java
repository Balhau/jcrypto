/**
 * O pacote balhau.crypto.coding pretende a implementação de mecanismos de codificação de dados.
 */
package balhau.crypto.coding;

import java.util.ArrayList;

import balhau.utils.ArrayUtils;

/**
 * Método que efectua a codificação binária para o formato base64
 * @author balhau
 *
 */
public class base64 {
	public static String COD="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	private byte[] _bytedata;
	private String _encstring;
	private int _posRead;
	private int _posEncRead;
	public static int EOF=-1;
	/**
	 * Construtor da classe com a especificação dos {@link byte}s a codificar
	 * @param cdbytes {@link byte[]} a codificar
	 */
	public base64(byte[] cdbytes){
		this._bytedata=cdbytes;
		this._posRead=0;
	}
	/**
	 * Construtor da classe sem especificação de parâmetros
	 */
	public base64(){
	}
	
	/**
	 * Especifica os {@link byte}s a codificar
	 * @param arr {@link byte[]} a codificar
	 */
	public void setByteArray(byte[] arr){
		this._bytedata=arr;
		this._posRead=0;
	}
	/**
	 * Método que especifica a {@link String} resultado de uma codificação {@link base64}
	 * @param strenc {@link String} codificada a partir do algoritmo presente em {@link base64}
	 */
	public void setEncodedString(String strenc){
		this._encstring=strenc;
		this._posEncRead=0;
	}
	/**
	 * Método que codifica um {@link byte[]} a partir do algoritmo {@link base64}
	 * @param cdbytes {@link byte[]} a codificar
	 * @return {@link String} com o valor codificado
	 */
	public String encode(byte[] cdbytes){
		StringBuilder b64enc=new StringBuilder("");
		int bt1,bt2,bt3;
		int enc1,enc2,enc3,enc4;
		this.setByteArray(cdbytes);
		while((bt1=this.readBytesBlock())!=base64.EOF){
			if((bt2=this.readBytesBlock())==base64.EOF){
				bt2=0;
				bt3=0;
				enc1=bt1>>2;
				enc2=((bt1&3)<<4)|(bt2>>4);
				enc3=64;
				enc4=64;
			}
			else if((bt3=this.readBytesBlock())==base64.EOF){
				bt3=0;
				enc1=bt1>>2;
				enc2=((bt1&3)<<4)|(bt2>>4);
				enc3=((bt2&15)<<2)|(bt3>>6);
				enc4=64;
			}
			else
			{
				enc1=bt1>>2;
				enc2=((bt1&3)<<4)|(bt2>>4);
				enc3=((bt2&15)<<2)|(bt3>>6);
				enc4=bt3&63;
			}
			
			b64enc.append(""+base64.COD.charAt(enc1)+base64.COD.charAt(enc2)+base64.COD.charAt(enc3)+base64.COD.charAt(enc4));
		}
		return b64enc.toString();
	}
	/***
	 * Codifica base64 por blocos
	 * @param cdbytes {@link byte[]} Array de bytes de dimensão 4
	 * @return {@link String} porção de informação codificada em base64
	 */
	public String encodeBlock(byte[] cdbytes){
		StringBuilder b64enc=new StringBuilder("");
		int bt1,bt2,bt3;
		int enc1,enc2,enc3,enc4;
		this.setByteArray(cdbytes);
		if((bt1=this.readBytesBlock())!=base64.EOF){
			if((bt2=this.readBytesBlock())==base64.EOF){
				bt2=0;
				bt3=0;
				enc1=bt1>>2;
				enc2=((bt1&3)<<4)|(bt2>>4);
				enc3=64;
				enc4=64;
			}
			else if((bt3=this.readBytesBlock())==base64.EOF){
				bt3=0;
				enc1=bt1>>2;
				enc2=((bt1&3)<<4)|(bt2>>4);
				enc3=((bt2&15)<<2)|(bt3>>6);
				enc4=64;
			}
			else
			{
				enc1=bt1>>2;
				enc2=((bt1&3)<<4)|(bt2>>4);
				enc3=((bt2&15)<<2)|(bt3>>6);
				enc4=bt3&63;
			}
			
			b64enc.append(""+base64.COD.charAt(enc1)+base64.COD.charAt(enc2)+base64.COD.charAt(enc3)+base64.COD.charAt(enc4));
		}
		return b64enc.toString();
	}
	/**
	 * Método que codifica o {@link byte[]} especificado na classe
	 * @return {@link String} com o valor codificado
	 */
	public String encode(){
		return this.encode(this._bytedata);
	}
	/**
	 * Método que codifica um {@link char[]} 
	 * @param charr {@link char[]} a codificar
	 * @return {@link String} com o valor codificado
	 */
	public String encode(char[] charr){
		return encode(ArrayUtils.ArrayCharToByte(charr));
	}
	
	public void setString(String str){
		setByteArray(ArrayUtils.ArrayCharToByte(str.toCharArray()));
	}
	
	/**
	 * Método que descodifica uma {@link String} codificada a partir do algoritmo {@link base64}
	 * @param basest {@link String} com o valor codificado
	 * @return {@link byte[]} com a informação descodificada
	 */
	public byte[] decode(String basest){
		ArrayList<Byte> btArr=new ArrayList<Byte>();
		byte bt1,bt2,bt3;
		Integer ch1,ch2,ch3,ch4;
		this.setEncodedString(basest);
		while((ch1=this.readEncStringBlock())!=base64.EOF){
			if((ch2=this.readEncStringBlock())==base64.EOF)
				return null;
			if((ch3=this.readEncStringBlock())==base64.EOF)
				return null;
			if((ch4=this.readEncStringBlock())==base64.EOF)
				return null;
			bt1=(byte) ((ch1.byteValue()<<2)|(ch2.byteValue()>>4));
			if(ch3==64){
				bt2=0;
				bt3=0;
			}
			else if(ch4==64){
				bt2=(byte) (((ch2.byteValue()&15)<<4)|ch3>>2);
				bt3=0;
				
			}
			else
			{
				bt2=(byte) (((ch2.byteValue()&15)<<4)|ch3>>2);
				bt3=(byte) (((ch3.byteValue()&3)<<6)|ch4.byteValue());
			}
			btArr.add(bt1);
			if(ch3!=64)
				btArr.add(bt2);
			if(ch4!=64)
				btArr.add(bt3);
		}
		return ArrayUtils.ArrayObjectToByte(btArr.toArray());
	}
	
	/**
	 * Efectua a descodificação por blocos
	 * @param basest {@link String} de 4 caracteres
	 * @return {@link byte[]} Array de bytes correspondentes ao bloco descodificado 
	 */
	public byte[] decodeBlock(String basest){
		ArrayList<Byte> btArr=new ArrayList<Byte>();
		byte bt1,bt2,bt3;
		Integer ch1,ch2,ch3,ch4;
		this.setEncodedString(basest);
		if((ch1=this.readEncStringBlock())!=base64.EOF){
			if((ch2=this.readEncStringBlock())==base64.EOF)
				return null;
			if((ch3=this.readEncStringBlock())==base64.EOF)
				return null;
			if((ch4=this.readEncStringBlock())==base64.EOF)
				return null;
			bt1=(byte) ((ch1.byteValue()<<2)|(ch2.byteValue()>>4));
			if(ch3==64){
				bt2=0;
				bt3=0;
			}
			else if(ch4==64){
				bt2=(byte) (((ch2.byteValue()&15)<<4)|ch3>>2);
				bt3=0;
				
			}
			else
			{
				bt2=(byte) (((ch2.byteValue()&15)<<4)|ch3>>2);
				bt3=(byte) (((ch3.byteValue()&3)<<6)|ch4.byteValue());
			}
			btArr.add(bt1);
			if(ch3!=64)
				btArr.add(bt2);
			if(ch4!=64)
				btArr.add(bt3);
		}
		return ArrayUtils.ArrayObjectToByte(btArr.toArray());
	}
	
	private int readBytesBlock(){
		int baux;
		if(this._posRead<this._bytedata.length){
			baux=(int)this._bytedata[this._posRead];
			if(baux<0)
				baux+=256;
			this._posRead++;
			return baux;                      
		}
		return base64.EOF;
	}
	
	private int readEncStringBlock(){
		int baux;
		if(this._posEncRead<this._encstring.length()){
			baux=base64.COD.indexOf(this._encstring.charAt(this._posEncRead));
			this._posEncRead++;
			return baux;
		}
		return base64.EOF;
	}
}
