package balhau.crypto;

/**
 * Classe que representa o mecanismo genérico para construção de uma Cifra de substituição.
 * Uma cifra de substituição consiste em efectuar uma permutação do alfabeto. A mensagem cifrada
 * é determinada mapeando cada caracter da mensagem na correspondente permutação. A decriptação
 * baseia-se no mecanismo inverso.
 * @author Balhau
 *
 */
public class SubsCifra {
	//A chave consiste num array de inteiros representando a permutação 
	private int[] _chave;
	private int _offset;
	public SubsCifra(){
		//inicializa o array
		this._chave=new int[26];
		this._offset=(int)'a';
		//a permutação inicial é a permutação identidade
		resetChave();
	}
	/**
	 * Método que devolve a chave identidade
	 */
	private void resetChave(){
		for(int i=0;i<26;i++)
			this._chave[i]=i;
	}
	/**
	 * Devolve o array que representa a chave de permutações
	 * @return Array de {@link int} representando a chave de permutações
	 */
	public int[] getChave(){
		return this._chave;
	}
	/**
	 * Efectua sucessivas permutações aleatórias de modo a criar uma chave pseudo-aleatória.
	 * A permutação chave é gravada na propriedade privada _chave e pode ser vista com o método {@link getChave}
	 * @param nperm {@link int} representando o número de trocas de posições necessárias até que a chave
	 * seja gerada
	 */
	private void criaChave(int nperm){
		int aux;
		int posi;
		int posf;
		for(int i=0;i<nperm;i++){
			posi=(int)Math.floor(Math.random()*25);
			posf=(int)Math.floor(Math.random()*25);
			aux=this._chave[posi];
			this._chave[posi]=this._chave[posf];
			this._chave[posf]=aux;
		}
	}
	
	/**
	 * Método público utilizado para gerar novas chaves
	 */
	public void novaChave(){
		this.criaChave(100);
	}
	/**
	 * Método que codifica uma {@link String} a partir do algoritmo de substituição
	 * @param plaintext {@link String} a codificar
	 * @return {@link String} codificada
	 */
	public String encoding(String plaintext){
		StringBuilder sb=new StringBuilder();
		plaintext=plaintext.toLowerCase();
		char car;
		//Itera sobre as letras da string alerando em função da permutação presente na chave
		for(int i=0;i<plaintext.length();i++){
			car=(char)(this._chave[((int)plaintext.charAt(i)-this._offset)]+this._offset);
			sb.append(car);
		}
		return sb.toString();
	}
	/**
	 * Método que descodifica uma {@link String} pelo presente algoritmo
	 * @param ciphertext {@link String} representando o texto criptografado
	 * @return Plaintext {@link String}
	 */
	public String decoding(String ciphertext){
		StringBuilder sb=new StringBuilder();
		ciphertext=ciphertext.toLowerCase();
		char car;
		//Itera sobre as letras da string alerando em função da permutação presente na chave
		for(int i=0;i<ciphertext.length();i++){
			car=(char)(findIndex((int)ciphertext.charAt(i)-this._offset,this._chave)+this._offset);
			sb.append(car);
		}
		return sb.toString();
	}
	
	/**
	 *  Método que devolve o índice onde se encontra o valor no array
	 * @param val Valor {@link int} a comparar 
	 * @param arrval Array {@link int[]} com os valores
	 * @return Posição {@link int} do valor no Array
	 */
	private int findIndex(int val,int[] arrval)
	{
		for(int i=0;i<arrval.length;i++){
			if(val==arrval[i])
				return i;
		}
		return -1;
	}
}
