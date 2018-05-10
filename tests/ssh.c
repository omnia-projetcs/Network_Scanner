//----------------------------------------------------------------
#include "../resources.h"
//----------------------------------------------------------------
ssh_session ssh_session_init(char *ip, unsigned int port)
{
  ssh_session my_ssh_session = ssh_new();
  if (my_ssh_session == NULL) return 0;//SSH_ERROR;

  //start session
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip);
  int timeout = SSH_TIMEOUT_MAX;
  ssh_options_set(my_ssh_session, SSH_OPTIONS_TIMEOUT, (const void*)&timeout);

  if (ssh_connect(my_ssh_session) != SSH_OK)
  {
    ssh_free(my_ssh_session);
    return 0;//SSH_ERROR_CONNECT;
  }

  //check session key
  int state = ssh_is_server_known(my_ssh_session);

  //get new hash
  unsigned char *hash = NULL;
  int hlen = ssh_get_pubkey_hash(my_ssh_session, &hash);
  if (hlen < 0)
  {
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return 0;//SSH_ERROR_PUBKEY;
  }

  switch(state)
  {
    case SSH_SERVER_KNOWN_OK:break; //ok

    case SSH_SERVER_KNOWN_CHANGED:  //interception of SSH flow !!!
    case SSH_SERVER_FOUND_OTHER:
    {
      ssh_disconnect(my_ssh_session);
      ssh_free(my_ssh_session);
      return 0;//SSH_ERROR_PUBKEY_HACK;
    }
    break;
    case SSH_SERVER_FILE_NOT_FOUND: //unknow adding to the trust host
    case SSH_SERVER_NOT_KNOWN:
    {
      if (ssh_write_knownhost(my_ssh_session) < 0)
      {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return 0;//SSH_ERROR_PUBKEY_ADD;
      }
    }
    break;
    case SSH_SERVER_ERROR:  //unknow state
    default:
    {
      ssh_disconnect(my_ssh_session);
      ssh_free(my_ssh_session);
      return 0;//SSH_ERROR_PUBKEY_UNKNOW;
    }
    break;
  }

  return my_ssh_session;
}
//----------------------------------------------------------------
BOOL ssh_session_Auth(ssh_session my_ssh_session, char*username, char*password)
{
  if (ssh_userauth_password(my_ssh_session, username, password) != SSH_AUTH_SUCCESS)
  {
    return FALSE;//SSH_ERROR_AUTHENTICATION;
  }return TRUE;
}
//----------------------------------------------------------------
ssh_channel ssh_open_channel(ssh_session my_ssh_session)
{
  //open channel for exec
  ssh_channel channel = ssh_channel_new(my_ssh_session);
  if (channel != NULL)
  {
    if (ssh_channel_open_session(channel) == SSH_OK)
    {
      return channel;
    }else ssh_channel_free(channel);
  }
  return FALSE;
}
//----------------------------------------------------------------
/*char *ConvertLinuxToWindows(char *src, DWORD max_size)
{
  char dst[max_size*2];
  DWORD i, j;
  DWORD src_size = strlen(src);
  DWORD dst_size_max = max_size*2;
  for (i=0,j=0;i<src_size && j<dst_size_max;i++)
  {
    switch(src[i])
    {
      case '\n':
        if (j+1 < dst_size_max && src[i+1] != '\n')
        {
          dst[j++] = '\r';
          dst[j++] = '\n';
        }
      break;
      //case '\t':dst[j++] = ' ';break;
      case '"':
        if (j+1 < dst_size_max)
        {
          dst[j++] = '\'';
          dst[j++] = '\'';
        }
      break;
      default:
        if (src[i] != 0 && src[i] > 31 && src[i] < 127)dst[j++] = src[i];
        else dst[j++] = ' ';
      break;
    }
  }
  dst[j] = 0;
  snprintf(src,max_size,"%s",dst);
  return src;
}*/
//----------------------------------------------------------------
int ssh_exec_cmd(DWORD iitem, char *ip, unsigned int port, char*username, char*password, long int id_account, char *cmd, char *buffer, DWORD buffer_size, BOOL msg_OK, BOOL msg_auth)
{
  if (buffer != NULL)buffer[0] = 0;
  long int ret = ssh_exec_(ip, port, username, password, cmd, buffer, buffer_size);

  char msg[MAX_MSG_SIZE+1]="";

  if (msg_OK)
  {
    snprintf(msg,MAX_MSG_SIZE,"(SSH) Enable on %s:%d",ip,port);
    AddMsg(h_main,(char*)"INFORMATION",msg,(char*)"",FALSE);
    AddLSTVUpdateItem(msg, COL_SSH, iitem);
  }

  if (msg_auth)
  {
    if (id_account == -1)
    {
      snprintf(msg,sizeof(msg),"%s:%d with %s account.",ip,port,username);
      if(!LOG_LOGIN_DISABLE)AddMsg(h_main,(char*)"LOGIN (SSH)",msg,(char*)"",FALSE);

      snprintf(msg,sizeof(msg),"Login SSH %s:%d with %s account.",ip,port,username);
      AddLSTVUpdateItem(msg, COL_CONFIG, iitem);
    }else
    {
      snprintf(msg,sizeof(msg),"%s:%d with %s (%02d) account.",ip,port,username,(unsigned int)id_account);
      if(!LOG_LOGIN_DISABLE)AddMsg(h_main,(char*)"LOGIN (SSH)",msg,(char*)"",FALSE);

      snprintf(msg,sizeof(msg),"Login SSH %s:%d with %s (%02d) account.",ip,port,username,(unsigned int)id_account);
      AddLSTVUpdateItem(msg, COL_CONFIG, iitem);
    }
  }
  return ret;
}
//----------------------------------------------------------------
int ssh_exec(DWORD iitem, char *ip, unsigned int port, char*username, char*password)
{
  DWORD i, _nb_i = SendDlgItemMessage(h_main,CB_T_SSH,LB_GETCOUNT,(WPARAM)NULL,(LPARAM)NULL);
  char cmd[MAX_MSG_SIZE+1], msg[MAX_MSG_SIZE+1];
  char *buffer;

  long int ret = SSH_ERROR;

  for (i=0;i<_nb_i && scan_start;i++)
  {
    cmd[0] = 0;
    if (SendDlgItemMessage(h_main,CB_T_SSH,LB_GETTEXTLEN,(WPARAM)i,(LPARAM)NULL) > MAX_MSG_SIZE)continue;
    if (SendDlgItemMessage(h_main,CB_T_SSH,LB_GETTEXT,(WPARAM)i,(LPARAM)cmd))
    {
      if (cmd[0] == 0 || cmd[0] == '\r' || cmd[0] == '\n')continue;
      else
      {
        buffer = NULL;
        if (ssh_exec_(ip, port, username, password, cmd, buffer, -1) == SSH_ERROR_OK)
        {
          snprintf(msg,MAX_MSG_SIZE,"\r\n[%s:%d\\%s]",ip,port,cmd);
          AddLSTVUpdateItem(msg, COL_SSH, iitem);

          AddMsg(h_main,(char*)"FOUND (SSH)",msg,buffer,FALSE);
          AddLSTVUpdateItem(buffer, COL_SSH, iitem);

          ret = SSH_ERROR_OK;
        }
        free(buffer);
      }
    }
  }
  return ret;
}
//----------------------------------------------------------------
long int ssh_exec_(char *ip, unsigned int port, char*username, char*password, char *cmd, char* buffer, long int buffer_max_sz)
{
  ssh_session my_ssh_session = ssh_session_init(ip, port);
  if (my_ssh_session == 0) return SSH_ERROR_CONNECT;

  long int ret = SSH_ERROR_AUTH;

  if (ssh_session_Auth(my_ssh_session, username, password))
  {
    ssh_channel channel = ssh_open_channel(my_ssh_session);
    if(channel != 0)
    {
      //run command "cmd"
      if (ssh_channel_request_exec(channel, cmd) == SSH_OK)
      {
        BOOL realoc = FALSE;
        long int buffer_sz = 0;

        if (buffer_max_sz == -1)
        {
          buffer = (char*)malloc (sizeof(char) * MAX_MSG_SIZE);
          if (buffer != NULL)
          {
            buffer_sz = MAX_MSG_SIZE;
            realoc = TRUE;
          }
        }else if (buffer_max_sz > 0)buffer_sz = buffer_max_sz;
        else{} //no read action by default

        ret = SSH_ERROR_OK;

        //read
        if (buffer_sz != 0)
        {
          long int nbytes = 0, total_sz = 0;
          char *buffer2;

          do
          {
            nbytes   = ssh_channel_read(channel, buffer+total_sz, buffer_sz-total_sz, 0);
            total_sz += nbytes;

            if (buffer[total_sz-1] == 0)break;
            if (nbytes < buffer_sz)buffer[total_sz-1] = 0;
            else buffer[total_sz-1] = 0;

            if (total_sz >= (buffer_sz-1))
            {
              buffer_sz = buffer_sz + buffer_sz;
              buffer2 = (char*)realloc(buffer, buffer_sz);
              if (buffer2 == NULL)break;
              else buffer = buffer2;
            }
          }while (nbytes >0);

          if (total_sz == 0 && realoc)
          {
            free(buffer);
            buffer = 0;
          }

          ret = total_sz;
          if (ret > 0 && buffer != 0)
          {
            ConvertLinuxToWindows(buffer, ret);
            ret= SSH_ERROR_OK;
          }
        }
      }
      ssh_channel_free(channel);
    }else ret = SSH_ERROR_OPEN_CHANNEL;
  }
  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);

  return ret;
}
//----------------------------------------------------------------
long int ssh_exec_all(DWORD iitem, char *ip, unsigned int port, char*username, char*password)
{
  DWORD i, nb_i = SendDlgItemMessage(h_main,CB_T_SSH,LB_GETCOUNT,(WPARAM)NULL,(LPARAM)NULL);
  long int ret;
  char buffer[MAX_LINE_SIZE],  cmd[MAX_MSG_SIZE], msg[MAX_MSG_SIZE+1];

  for (i=0;i<nb_i && scan_start;i++)
  {
    cmd[0] = 0;
    if (SendDlgItemMessage(h_main,CB_T_SSH,LB_GETTEXTLEN,(WPARAM)i,(LPARAM)NULL) > MAX_MSG_SIZE)continue;
    if (SendDlgItemMessage(h_main,CB_T_SSH,LB_GETTEXT,(WPARAM)i,(LPARAM)cmd))
    {
      if (cmd[0] == 0 || cmd[0] == '\r' || cmd[0] == '\n')continue;

      memset(buffer,0,MAX_LINE_SIZE);
      ret = ssh_exec_(ip, port, username, password, cmd, buffer, MAX_LINE_SIZE);
      if (ret == SSH_ERROR_AUTH) return SSH_ERROR_AUTH;
      else if (ret >=0)
      {
        if (buffer[0] != 0)
        {
          ConvertLinuxToWindows(buffer, MAX_MSG_SIZE);
          snprintf(msg,MAX_MSG_SIZE,"\r\n[%s:%d\\%s]\r\n",ip,port,cmd);
          AddMsg(h_main,(char*)"FOUND (SSH)",msg,buffer,FALSE);
          AddLSTVUpdateItem(buffer, COL_SSH, iitem);
        }
      }else return ret;
    }
  }
  return SSH_ERROR_OK;
}
//----------------------------------------------------------------
int ssh_exec_to_file(DWORD iitem, char *ip, unsigned int port, char*username, char*password, HANDLE hfile)
{
  return (int) ssh_exec_all_to_file(iitem, ip, port, username, password, hfile, TRUE);
}
//----------------------------------------------------------------
long int ssh_exec_all_to_file(DWORD iitem, char *ip, unsigned int port, char*username, char*password, HANDLE hfile, BOOL log)
{
  ssh_session my_ssh_session = ssh_session_init(ip, port);
  if (my_ssh_session == 0) return SSH_ERROR;

  long int ret = SSH_ERROR;

  if (ssh_session_Auth(my_ssh_session, username, password))
  {
    ssh_channel channel = ssh_open_channel(my_ssh_session);
    if(channel != 0)
    {
      //allocate memory !
      char buffer[MAX_MSG_SIZE],cmd[MAX_MSG_SIZE], msg[MAX_MSG_SIZE+1];
      long int nbytes = 0;
      DWORD copiee;

      DWORD i, nb_i = SendDlgItemMessage(h_main,CB_T_SSH,LB_GETCOUNT,(WPARAM)NULL,(LPARAM)NULL);
      for (i=0;i<nb_i && scan_start;i++)
      {
        nbytes = 0;
        cmd[0] = 0;
        if (SendDlgItemMessage(h_main,CB_T_SSH,LB_GETTEXTLEN,(WPARAM)i,(LPARAM)NULL) > MAX_MSG_SIZE)continue;
        if (SendDlgItemMessage(h_main,CB_T_SSH,LB_GETTEXT,(WPARAM)i,(LPARAM)cmd))
        {
          if (cmd[0] == 0 || cmd[0] == '\r' || cmd[0] == '\n')continue;

          if (ssh_channel_request_exec(channel, cmd) == SSH_OK)
          {
            do
            {
              nbytes   = ssh_channel_read(channel, buffer, MAX_MSG_SIZE, 0);
              if (nbytes > 0)
              {
                if (buffer[0] == 0)break;
                if (nbytes < MAX_MSG_SIZE)buffer[nbytes] = 0;
                else buffer[MAX_MSG_SIZE-1] = 0;

                ConvertLinuxToWindows(buffer, MAX_MSG_SIZE);
                snprintf(msg,MAX_MSG_SIZE,"\r\n[%s:%d\\%s]\r\n",ip,port,cmd);

                if (log)
                {
                  AddMsg(h_main,(char*)"FOUND (SSH)",msg,buffer,FALSE);
                  AddLSTVUpdateItem(msg,    COL_SSH, iitem);
                  AddLSTVUpdateItem(buffer, COL_SSH, iitem);
                }

                //add to file
                WriteFile(hfile,msg,strlen(msg),&copiee,0);
                WriteFile(hfile,buffer,strlen(buffer),&copiee,0);

                buffer[0] = 0;
              }
            }while (nbytes >0);

            ret = SSH_ERROR_OK;
          }
        }
      }
      ssh_channel_free(channel);
    }
  }
  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);

  return ret;
}
//----------------------------------------------------------------
long int ssh_get_OS(char *ip, unsigned int port, char*username, char*password, char*os, unsigned int os_max_sz)
{
  os[0] = 0;
  long int ret = ssh_exec_(ip, port, username, password, (char*)"lsb_release -d -s", os, os_max_sz);
  if (ret >= 0)
  {
    #ifdef DEBUG_SSH_MODE
    char tmp_b[MAX_LINE_SIZE];
    snprintf(tmp_b, MAX_LINE_SIZE, "ssh_get_OS - ssh_exec_ (lsb_release -d -s) : %s", os);
    AddMsg(h_main, (char*)"DEBUG", (char*)tmp_b, (char*)ip, FALSE);
    #endif

    int ret_os = LinuxStart_msgOK(os, (char*)"lsb_release -d -s");
    if (ret_os == -1) return SSH_ERROR_AUTH;

    if (os[0] == 0 || ret_os == FALSE)
    {
      ret = ssh_exec_(ip, port, username, password, (char*)"head -n 1 /etc/issue", os, os_max_sz);
      if (ret >= 0)
      {
        #ifdef DEBUG_SSH_MODE
        char tmp_b[MAX_LINE_SIZE];
        snprintf(tmp_b, MAX_LINE_SIZE, "ssh_get_OS - ssh_exec_ (head -n 1 /etc/issue) : %s", os);
        AddMsg(h_main, (char*)"DEBUG", (char*)tmp_b, (char*)ip, FALSE);
        #endif

        ret_os = LinuxStart_msgOK(os, (char*)"head -n 1 /etc/issue");
        if (ret_os == -1) return SSH_ERROR_AUTH;

        if (os[0] == 0 || ret_os)
        {
          ret = ssh_exec_(ip, port, username, password, (char*)"uname -a", os, os_max_sz);
          if (ret >= 0)
          {
            #ifdef DEBUG_SSH_MODE
            char tmp_b[MAX_LINE_SIZE];
            snprintf(tmp_b, MAX_LINE_SIZE, "ssh_get_OS - ssh_exec_ (uname -a) : %s", os);
            AddMsg(h_main, (char*)"DEBUG", (char*)tmp_b, (char*)ip, FALSE);
            #endif

            ret_os = LinuxStart_msgOK(os, (char*)"uname -a");
            if (ret_os == -1) return SSH_ERROR_AUTH;

            if (os[0] == 0 || ret_os)
            {
              os[0] = 0;
              return SSH_ERROR;
            }else
            {
              char tmp_os[SSH_OS_SZ_MAX];
              if (os[0] == '\'')snprintf(tmp_os, SSH_OS_SZ_MAX, "%s", os+1);
              else snprintf(tmp_os, SSH_OS_SZ_MAX, "%s", os);

              if (tmp_os[0] == '\'')snprintf(os, os_max_sz, "%s", tmp_os+1);
              else snprintf(os, os_max_sz, "%s", tmp_os);

              #ifdef DEBUG_SSH_MODE
              AddMsg(h_main, (char*)"DEBUG", (char*)"ssh_get_OS - ssh_exec_ : OK2", (char*)ip, FALSE);
              #endif
            }
          }
        }else
        {
          char tmp_os[SSH_OS_SZ_MAX];
          if (os[0] == '\'')snprintf(tmp_os, SSH_OS_SZ_MAX, "%s", os+1);
          else snprintf(tmp_os, SSH_OS_SZ_MAX, "%s", os);

          if (tmp_os[0] == '\'')snprintf(os, os_max_sz, "%s", tmp_os+1);
          else snprintf(os, os_max_sz, "%s", tmp_os);

          #ifdef DEBUG_SSH_MODE
          AddMsg(h_main, (char*)"DEBUG", (char*)"ssh_get_OS - ssh_exec_ : OK1", (char*)ip, FALSE);
          #endif
        }
      }
    }else
    {
      char tmp_os[SSH_OS_SZ_MAX];
      if (os[0] == '\'')snprintf(tmp_os, SSH_OS_SZ_MAX, "%s", os+1);
      else snprintf(tmp_os, SSH_OS_SZ_MAX, "%s", os);

      if (tmp_os[0] == '\'')snprintf(os, os_max_sz, "%s", tmp_os+1);
      else snprintf(os, os_max_sz, "%s", tmp_os);

      #ifdef DEBUG_SSH_MODE
      AddMsg(h_main, (char*)"DEBUG", (char*)"ssh_get_OS - ssh_exec_ : OK0", (char*)ip, FALSE);
      #endif
    }
  }
  return ret;
}
