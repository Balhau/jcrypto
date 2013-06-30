package balhau.crypto;


import balhau.utils.ArrayUtils;

/**
 * Extensão da cifra de César para todos os caracteres ASCII.
 * @author Balhau
 *
 */
public class ASCIICeaser {
	private int _shift;
	/**
	 * Construtor para a cifra de César
	 * @param shift {@link Integer} representando o deslocamento da cifra
	 */
	public ASCIICeaser(int shift){
		this._shift=shift%256;
	}
	
	/**
	 * Método que codifica uma ascii string pelo método de César
	 * @param str {@link String} para codificar
	 * @return {@link String} codificada
	 */
	public String encode(String str){
		char[] carr=str.toCharArray();
		char[] cod=new char[carr.length];
		for(int i=0;i<carr.length;i++){
			cod[i]=(char)(((int)carr[i]+this._shift)%255);
		}
		return ArrayUtils.ArrayCharToString(cod);
	}
	
	/**
	 * Método que descodifica uma ascii string codificada pelo método de César
	 * @param str {@link String} codificada
	 * @return {@link String} descodificada
	 */
	public String decode(String str){
		char[] carr=str.toCharArray();
		char[] decod=new char[carr.length];
		for(int i=0;i<carr.length;i++){
			decod[i]=(char)(((int)carr[i]+255-this._shift)%255);
		}
		return ArrayUtils.ArrayCharToString(decod);
	}
}
