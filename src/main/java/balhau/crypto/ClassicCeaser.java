package balhau.crypto;
/**
 * Classe que codifica, e descodifica uma string a partir do algoritmo clássico
 * de Ceaser
 * @author balhau
 *
 */
public class ClassicCeaser {
	private int _shift;
	private int _offset;
	
	/**
	 * Construtor da classe.
	 * @param shift {@link Integer} representa o desclocamento efectuado
	 * para a permutação de César
	 */
	public ClassicCeaser(int shift){
		this._shift=shift%26;
		this._offset=(int)'a';
	}
	/**
	 * Método que codifica uma {@link String} contendo comente caracteres
	 * do alfabeto a partir da cifra clássica de César
	 * @param str {@link String} contendo a mensagem a codificar
	 * @return {@link String} mensagem codificada pela cifra de César
	 */
	public String encode(String str)
	{
		StringBuilder sb=new StringBuilder("");
		String aux=str.toLowerCase();
		char c;
		for(int i=0;i<str.length();i++){
			c=(char)(((((int)aux.charAt(i)-this._offset)+this._shift)%26)+this._offset);
			sb.append(c);
		}
		return sb.toString();
	}
	
	/**
	 * Descodifica uma string codificada pela cifra de César
	 * @param str {@link String} mensagem codificada pelo algoritmo de César
	 * @return {@link String} mensagem descodificada pelo algoritmo de César
	 */
	public String decode(String str){
		StringBuilder sb=new StringBuilder("");
		String aux=str.toLowerCase();
		char c;
		for(int i=0;i<str.length();i++){
			c=(char)(((((int)aux.charAt(i)-this._offset)-this._shift+26)%26)+this._offset);
			sb.append(c);
		}
		return sb.toString();
	}
	
	
}
