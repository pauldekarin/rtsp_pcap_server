package com.company.pauldekarin;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.classfile.AnnotationValue.OfByte;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.sql.Time;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import javax.management.Descriptor;
import javax.print.DocFlavor.STRING;
import javax.swing.Timer;
import org.jnetpcap.BpFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.util.PcapPacketRef;

public class RTSPServer implements ActionListener {
  DatagramSocket RTPSocket;

  final static int RTSPPort = 5554;
  final static String CRLF = "\r\n";

  static String RTSPid = UUID.randomUUID().toString();

  final static int INIT = 0;
  final static int READY = 1;
  final static int PLAYING = 2;

  final static int SETUP = 3;
  final static int PLAY = 4;
  final static int PAUSE = 5;
  final static int TEARDOWN = 6;
  final static int DESCRIBE = 7;
  final static int OPTIONS = 8;

  final static int FRAME_DELAY = 20;

  Timer timer;
  int sendDelay;
  int RTSPSeqNb = 0;
  List<Integer> RTPDestPorts;

  static int state = -1;

  Socket RTSPSocket;
  InetAddress IPAddr;
  int PCAPPacketIndex = 0;
  long previousTimestamp = 0;
  static BufferedReader RTSPBufferedReader;
  static BufferedWriter RTSPBufferedWriter;
  final static String PCAP_FILEPATH = System.getProperty("user.dir").concat("/bunny.pcapng");

  static Pcap pcap;
  static Pcap PCAPAudio;

  public RTSPServer() {
    sendDelay = FRAME_DELAY;
    RTPDestPorts = new ArrayList<Integer>();
  }

  static public void main(String[] args) throws IOException, PcapException {
    RTSPServer rtspServer = new RTSPServer();

    pcap = Pcap.openOffline(PCAP_FILEPATH);

    BpFilter filter = pcap.compile("udp", true);
    pcap.setFilter(filter);

    ServerSocket masterSocket = new ServerSocket(RTSPPort);
    rtspServer.RTSPSocket = masterSocket.accept();
    masterSocket.close();

    rtspServer.IPAddr = rtspServer.RTSPSocket.getInetAddress();

    RTSPBufferedReader =
        new BufferedReader(new InputStreamReader(rtspServer.RTSPSocket.getInputStream()));
    RTSPBufferedWriter =
        new BufferedWriter(new OutputStreamWriter(rtspServer.RTSPSocket.getOutputStream()));

    state = INIT;

    int reqType;
    boolean done = false;

    while (!done) {
      reqType = rtspServer.parseRTSPRequest();

      if (reqType == OPTIONS) {
        rtspServer.sendResponse("Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, OPTIONS");
      } else if (reqType == DESCRIBE) {
        rtspServer.sendDescribe();
      } else if (reqType == SETUP) {
        rtspServer.RTPSocket = new DatagramSocket();
        String resp = "Transport: RTP/AVP;unicast;client_port="
            + Integer.toString(rtspServer.RTPDestPorts.getLast()) + CRLF + "Session: " + RTSPid
            + ";timeout=60" + CRLF;
        rtspServer.sendResponse(resp);

        state = READY;
      } else if (reqType == PLAY) {
        if (state == READY) {
          rtspServer.sendResponse();

          rtspServer.timer = new Timer(rtspServer.sendDelay, rtspServer);
          rtspServer.timer.setInitialDelay(0);
          rtspServer.timer.setCoalesce(true);
          rtspServer.timer.start();

          state = PLAYING;
        }
      } else if (reqType == TEARDOWN) {
        rtspServer.sendResponse();
        rtspServer.timer.stop();
        rtspServer.RTSPSocket.close();
        rtspServer.RTPSocket.close();
        done = true;
      } else if (reqType == PAUSE) {
        if (state == PLAYING) {
          rtspServer.sendResponse();
          rtspServer.timer.stop();
          state = READY;
        }
      }
    }
  }

  @Override
  public void actionPerformed(ActionEvent e) {
    try {
      pcap.loop(-1, new PcapHandler.OfMemorySegment<String>() {
        @Override
        public void handleSegment(String user, MemorySegment header, MemorySegment packet) {
          try {
            Integer RTPDestPort = RTPDestPorts.get(0);
            switch (extractPortUDP(packet)) {
              case 49190:
                RTPDestPort = RTPDestPorts.get(RTPDestPorts.size() - 1);
                break;
              case 49188:
                RTPDestPort = RTPDestPorts.get(0);
                break;
            }

            byte[] buff = packet.asSlice(42).toArray(ValueLayout.JAVA_BYTE);
            DatagramPacket UDPPacket = new DatagramPacket(buff, buff.length, IPAddr, RTPDestPort);

            RTPSocket.send(UDPPacket);
          } catch (IOException err) {
            err.printStackTrace();
            System.exit(0);
          }
        }
      }, "msg");
    } catch (Exception err) {
      err.printStackTrace();
      System.exit(-1);
    }
  }

  public static int extractPortUDP(MemorySegment packet) {
    return Short.toUnsignedInt(
        Short.reverseBytes(packet.asSlice(36, 2).get(ValueLayout.JAVA_SHORT, 0)));
  }
  private static void displayMemorySegment(MemorySegment seg) {
    StringBuilder hexBuilder = new StringBuilder();
    Integer hexCount = 0;
    for (byte b : seg.toArray(ValueLayout.JAVA_BYTE)) {
      hexBuilder.append(String.format("%02x ", b));
      if (hexCount++ >= 15) {
        hexBuilder.append('\n');
        hexCount = 0;
      }
    }
    System.out.println(hexBuilder.toString());
  }

  private void sendResponse() {
    try {
      RTSPBufferedWriter.write("RTSP/1.0 200 OK" + CRLF);
      RTSPBufferedWriter.write("CSeq: " + RTSPSeqNb + CRLF);
      RTSPBufferedWriter.write("Server: localhost" + CRLF);
      RTSPBufferedWriter.write("Cache: no-cache" + CRLF);
      RTSPBufferedWriter.write("Session: " + RTSPid + CRLF);
      RTSPBufferedWriter.write(CRLF);
      RTSPBufferedWriter.flush();
    } catch (IOException e) {
    }
  }
  private void sendResponse(String msg) {
    try {
      RTSPBufferedWriter.write("RTSP/1.0 200 OK" + CRLF);
      RTSPBufferedWriter.write("CSeq: " + RTSPSeqNb + CRLF);
      RTSPBufferedWriter.write("Server: localhost" + CRLF);
      RTSPBufferedWriter.write("Cache: no-cache" + CRLF);
      RTSPBufferedWriter.write(msg + CRLF);
      RTSPBufferedWriter.write(CRLF);
      RTSPBufferedWriter.flush();
    } catch (IOException e) {
    }
  }

  private void sendDescribe() {
    String des = "RTSP/1.0 200 OK" + CRLF + "CSeq: 3" + CRLF
        + "Server: Wowza Streaming Engine 4.7.5.01 build21752" + CRLF + "Cache-Control: no-cache"
        + CRLF + "Content-Length: 581" + CRLF
        + "Content-Base: rtsp://localhost:5540/vod/mp4:BigBuckBunny_115k.mov/" + CRLF
        + "Content-Type: application/sdp" + CRLF + "Session: " + RTSPid + ";timeout=60" + CRLF
        + CRLF + "v=0" + CRLF + "o=- 1823687535 1823687535 IN IP4 127.0.0.1" + CRLF
        + "s=BigBuckBunny_115k.mov" + CRLF + "c=IN IP4 127.0.0.1" + CRLF + "t=0 0" + CRLF
        + "a=sdplang:en" + CRLF + "a=range:npt=0- 596.48" + CRLF + "a=control:*" + CRLF
        + "m=audio 0 RTP/AVP 96" + CRLF + "a=rtpmap:96 mpeg4-generic/12000/2" + CRLF
        + "a=fmtp:96 profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1490"
        + CRLF + "a=control:trackID=1" + CRLF + "m=video 0 RTP/AVP 97" + CRLF
        + "a=rtpmap:97 H264/90000" + CRLF
        + "a=fmtp:97 packetization-mode=1;profile-level-id=42C01E;sprop-parameter-sets=Z0LAHtkDxWhAAAADAEAAAAwDxYuS,aMuMsg=="
        + CRLF + "a=cliprect:0,0,160,240" + CRLF + "a=framesize:97 240-160" + CRLF
        + "a=framerate:24.0" + CRLF + "a=control:trackID=2" + CRLF;
    try {
      RTSPBufferedWriter.write("RTSP/1.0 200 OK" + CRLF);
      RTSPBufferedWriter.write("CSeq: " + RTSPSeqNb + CRLF);
      RTSPBufferedWriter.write("Server: localhost" + CRLF);
      RTSPBufferedWriter.write("Cache-Control: no-cache" + CRLF);
      RTSPBufferedWriter.write(des);
      RTSPBufferedWriter.write(CRLF);
      RTSPBufferedWriter.flush();
    } catch (Exception ex) {
      ex.printStackTrace();
      System.exit(0);
    }
  }
  private int parseRTSPRequest() {
    int reqType = -1;
    try {
      String RequestLine = RTSPBufferedReader.readLine();

      if (RequestLine == null || RequestLine.isEmpty())
        return reqType;
      System.out.println("*".repeat(10));
      System.out.println("[\033[32mRequestLine\033[0m]: " + RequestLine);

      StringTokenizer tokenizer = new StringTokenizer(RequestLine);
      String requestTypeString = tokenizer.nextToken();

      if ((new String(requestTypeString)).compareTo("SETUP") == 0)
        reqType = SETUP;
      else if ((new String(requestTypeString)).compareTo("PLAY") == 0)
        reqType = PLAY;
      else if ((new String(requestTypeString)).compareTo("PAUSE") == 0)
        reqType = PAUSE;
      else if ((new String(requestTypeString)).compareTo("TEARDOWN") == 0)
        reqType = TEARDOWN;
      else if ((new String(requestTypeString)).compareTo("DESCRIBE") == 0)
        reqType = DESCRIBE;
      else if ((new String(requestTypeString)).compareTo("OPTIONS") == 0)
        reqType = OPTIONS;

      String SeqNumLine = RTSPBufferedReader.readLine();
      System.out.println("[\033[32mSeqNumLinee\033[0m]: " + SeqNumLine);

      tokenizer = new StringTokenizer(SeqNumLine);
      tokenizer.nextToken();
      RTSPSeqNb = Integer.parseInt(tokenizer.nextToken());

      String LastLine = RTSPBufferedReader.readLine();
      System.out.println("[\033[32mLastLine\033[0m]: " + LastLine);

      if (reqType == SETUP) {
        while (!LastLine.contains("client_port")) LastLine = RTSPBufferedReader.readLine();
        String port = LastLine.substring(LastLine.lastIndexOf("=") + 1, LastLine.indexOf('-'));
        RTPDestPorts.add(Integer.parseInt(port));
      }

      do {
        RequestLine = RTSPBufferedReader.readLine();
      } while (!RequestLine.isEmpty());
      System.out.println("*".repeat(10));

    } catch (IOException e) {
    }
    return (reqType);
  }
}
