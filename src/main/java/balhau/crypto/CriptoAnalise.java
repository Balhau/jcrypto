package balhau.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import balhau.utils.Sys;
import balhau.utils.ArrayUtils;


/**
 * Classe que contém um conjunto de mecanismos de criptoanálise
 * @author Balhau
 *
 */
public class CriptoAnalise {
	/**
	 * Método que efectua a análise para uma string codificada pela cifra
	 * de ASCIICeaser
	 * @param cod {@link String} codificada
	 * @return Todas as {@link String} possiveis
	 */
	public static String AnaliseASCIICeaser(String cod){
		StringBuilder sb=new StringBuilder();
		sb.append("Criptoanálise para a cifra ASCIICeaser"+Sys.EOL);
		char[] arrcod=cod.toCharArray();
		char[] arrdec=new char[arrcod.length];
		for(int i=0;i<255;i++){
			for(int j=0;j<arrcod.length;j++){
				arrdec[j]=(char)(((int)arrcod[j]+255-i)%255);
			}
			sb.append("Ataque_"+i+": "+ArrayUtils.ArrayCharToString(arrdec)+Sys.EOL);
		}
		return sb.toString();
	}
	/**
	 * Método que testa todas as combinações para uma mensagem cofificada
	 * pela cifra de César.
	 * @param cod {@link String} mensagem codificada pela cifra de César 
	 * @return {@link String} conjunto das 26 mensagens possíveis
	 */
	public static String AnaliseClassicCeaser(String cod){
		StringBuilder sb=new StringBuilder();
		ClassicCeaser cl;
		sb.append("Criptoanálise para a cifra de ClassicCeaser"+Sys.EOL);
		for(int i=0;i<26;i++){
			cl=new ClassicCeaser(i);
			sb.append("shift "+i+": "+cl.decode(cod)+Sys.EOL);
		}
		return sb.toString();
	}
	/**
	 * Devolve um {@link HashMap} contendo as frequências para cada um
	 * dos caracteres da String
	 * @param str {@link String} que pretendemos analizar frequências
	 * @param rel {@link Boolean} indica se estamos na presença de frequencias relativas
	 * ou absolutas 
	 * @return {@link HashMap} com as frequências da string
	 */
	public static HashMap<String, Double> TabelaFreq(String str,Boolean rel){
		HashMap<String, Double> tb=new HashMap<String, Double>();
		int offset=(int)'a';
		for(int i=0;i<str.length();i++){
			if(tb.containsKey(""+str.charAt(i)))
				tb.put(""+str.charAt(i), tb.get(""+str.charAt(i))+1);
			else
				tb.put(""+str.charAt(i),1.0);
		}
		//adiciona as letras em falta
		for(int i=0;i<26;i++){
			if(!tb.containsKey(""+(char)(offset+i)))
				tb.put(""+(char)(offset+i),0.0);
		}
		if(rel){
			Object[] ks=tb.keySet().toArray();
			for(int j=0;j<ks.length;j++){
				tb.put((String)ks[j], tb.get(ks[j])/(double)str.length());
			}
		}
		return tb;
	}
	/**
	 * Método que imprime a tabela de frequências
	 * @param tb {@link HashMap} tabela de frequências
	 */
	public static void PrintFreqTable(HashMap<String, Double> tb){
		System.out.println("Frequencias :"+Sys.EOL);
		Object[] ks;
		for(int i=0;i<tb.size();i++){
			ks=tb.keySet().toArray();
			System.out.println("['"+ks[i]+"',"+tb.get(ks[i])+"]");
		}
	}
	/**
	 * Constrói a tabela de frequências a partir de um ficheiro
	 * @param urFile {@link String} nome do ficheiro
	 * @para rel Parametro booleano representando a presença de tabela de frequências relativas ou absolutas
	 * @return {@link HashMap} que representa a tabela de frequências
	 * @throws IOException Devolve um erro caso haja problemas na leitura do ficheiro 
	 */
	public static HashMap<String, Double> BuildFreqTableFromFile(String urFile,boolean rel) throws IOException
	{
		HashMap<String, Double> tb=new HashMap<String, Double>();
		File fl=new File(urFile);
		String linha;
		int i;
		int k=0;
		int offset=(int)'a';
		String grupo;
		BufferedReader bf=new BufferedReader(new FileReader(fl));
		Pattern pt=Pattern.compile("[a-z]*");
		Matcher mt;
		//le uma linha do ficheiro
		while((linha=bf.readLine())!=null){
			//Do ficheiro selecciona somente sequências alfabéticas
			mt=pt.matcher(linha);
			//das sequências encontradas contar a frequência dos caracteres
			while(mt.find()){
				grupo=mt.group();
				for(i=0;i<grupo.length();i++){
					if(tb.containsKey(""+grupo.charAt(i)))
						tb.put(""+grupo.charAt(i), tb.get(""+grupo.charAt(i))+1);
					else
						tb.put(""+grupo.charAt(i),1.0);
					k++;
				}
			}
		}
		for(int j=0;j<26;j++){
			if(!tb.containsKey(""+(char)(offset+j)))
				tb.put(""+(char)(offset+j),0.0);
		}
		if(rel){
			Object[] ks=tb.keySet().toArray();
			for(int j=0;j<ks.length;j++){
				tb.put((String)ks[j], tb.get(ks[j])/(double)k);
			}
		}
		return tb;
	}
	/**
	 * Método que devolve uma possível chave de encriptção utilizada no algoritmo {@link SubsCifra}.
	 * O algoritmo aqui utilizado associa uma entrada da tabela A a uma outra da tabela B que tenha probabilidade semelhante 
	 * @param tbA Tabela {@link HashMap} de frequencias A
	 * @param tbB Tabela {@link HashMap} de frequencias B
	 * @return Array {@link int[]} com uma possível chave de permutação
	 */
	public static int[] getChavePossivel(HashMap<String, Double> tbA,HashMap<String, Double> tbB){
		int[] pchave=new int[26];
		int pos;
		int cur=0;
		int[] par;
		Stack<Double> buffB=new Stack<Double>();
		Stack<Double> buffA=new Stack<Double>();
		Stack<Integer> buffIA=new Stack<Integer>();
		Stack<Integer> buffIB=new Stack<Integer>();
		String[] chvs=ArrayUtils.ArrayObjectToArrayString(tbA.keySet().toArray());
		//Copia os valores da hashtable para as stacks
		for(int i=0;i<26;i++){
			buffA.add(tbA.get(chvs[i]));
			buffB.add(tbB.get(chvs[i]));
			buffIA.add(i);
			buffIB.add(i);
		}
		//enquanto a stack não for vazia, seleccionar índices
		
		while(!buffIA.empty()){
			//escolhe uma posição da stackA para associar
			pos=(int)Math.floor(Math.random()*(buffIA.size()-1));
			par=getPar(buffA.get(pos), buffB,buffIB);
			pchave[cur]=par[0];
			buffIA.remove(pos);
			buffIB.remove(par[1]);
			cur++;
		}
		return pchave;
	}
	/**
	 * Método que devolve o índice do elemento mais próximo existente na stack 
	 * @param val Valor {@link Double} que se pretende comparar com a stack
	 * @param lista {@link Stack} com os valores
	 * @param lista {@link Stack} com o índices possíveis
	 * @return  {@link int} com a posição da stack do valor mais próximo
	 */
	private static int[] getPar(Double val,Stack<Double> lista,Stack<Integer> listaInd){
		int[] k=new int[2];
		double diff=Math.abs(lista.get(listaInd.get(0))-val);
		k[0]=listaInd.get(0);
		k[1]=0;
		for(int i=0;i<listaInd.size();i++){
			if(Math.abs(lista.get(listaInd.get(i))-val)<diff){
				k[0]=listaInd.get(i);
				k[1]=i;
			}
		}
		return k;
	}
}
