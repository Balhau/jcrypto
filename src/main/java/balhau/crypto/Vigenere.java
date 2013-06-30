package balhau.crypto;
/**
 * Implementa a encriptação de vigénere. Atenção este mecanismo codifica somente strings que contenham caracteres do alfabeto
 * @author Balhau
 *
 */
public class Vigenere {

	private String _chave;
	private int _offset;
	
	public Vigenere(String chave){
		this._chave=chave;
		this._offset=(int)'a';
	}
	
	/**
	 * Método que codifica uma string (contendo somente letras do alfabeto) a partir do algoritmo de Vigénere
	 * @param str {@link String} a codificar
	 * @return {@link String} codificada
	 */
	public String encode(String str){
		String aux=str.toLowerCase();
		String enc="";
		for(int i=0;i<str.length();i++){
			enc+=(char)(((((int)aux.charAt(i)-this._offset)+((int)this._chave.charAt(i%this._chave.length())-this._offset))%26)+this._offset);
		}
		return enc;
	}
	
	/**
	 * Método que descodifica uma {@link String} codificada pelo algoritmo de Vigénere
	 * @param str {@link String} com a mensagem codificada pelo algoritmo de Vigénere
	 * @return {@link String} com a mensagem descodificada
	 */
	public String decode(String str){
		String dec="";
		str=str.toLowerCase();
		for(int i=0;i<str.length();i++){
			dec+=(char)((((((int)str.charAt(i)-this._offset)-(((int)this._chave.charAt(i%this._chave.length())-this._offset)+26)%26)+26)%26)+this._offset);
		}
		return dec;
	}
}
