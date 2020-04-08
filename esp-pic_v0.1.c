//-----------------------------------------------------------------------------
void protocolo_esp_pic (void *pvParameters)
{
    //------------------------------------------------
    #define UART_BUFF_SIZE                      2048+2  //+2 = bytes de checksum incluidos
    #define SISTEMA_PACOTE_MAX                  0x0003
    //------------------------------------------------
    static uint8_t buff_in[UART_BUFF_SIZE];
    static uint8_t buff_out[UART_BUFF_SIZE];
    static uint16_t in_i;
    static uint16_t out_i;
    static uint8_t currentByteRead;
    static uint8_t previousByteRead;
    uint8_t byte;
    static uint8_t sys_req[2];
    static uint8_t sys_ans[2];
    //------------------------------------------------
    static bool idle = true;                            
    static bool sincronizacao_recebida = false;         //deve ser resetada antes de ir para idle
    static uint8_t checksum_byte_num = 1;               //deve ser resetada antes de ir para idle
    //------------------------------------------------
    static TickType_t ticks = UINT32_MAX;
    //------------------------------------------------

    //Em termos de ESP, mas pro PIC é tudo igual... 
    //por exemplo, se o ESP estiver querendo enviar um envio ou pedido para o PIC,
    //O ESP vai enviar uma requisicao 0x5500 e o PIC vai responder com 0x5502 (ou nao responder se estiver ocupado)
    //Cabe ao ESP ficar escrevendo os itens que sua queue possiu na porta serial para o PIC entao receber. 
    //Na fila do ESP, deve existir um tempo livre entre cada tentativa de envio, um delay, por exemplo 10ms (1 ticks)
    //1000ms/10ms = até 100 eventos de por segundo...

    //---------------------------------------------------------------
    // SISTEMA
    //---------------------------------------------------------------
    static const char SYS_CONSULTA_ESTADO[2] =           { 0x55, 0x00 };
    static const char SYS_RESPOSTA_ESTADO_PRONTO[2] =    { 0x55, 0x02 };
    static const char SYS_SINCRONIZACAO[2] =             { 0x55, 0x01 };
    static const char SYS_CONFIRMA_RECEPCAO[2] =         { 0x55, 0x04 };    //aqui ja se considera o checksum como ok  
    static const char SYS_ERRO_CHECKSUM[2] =             { 0x55, 0x05 };
    static const char SYS_ERRO_TIMEOUT[2] =              { 0x55, 0x06 };
    static const char SYS_ERRO_TAMANHO[2] =              { 0x55, 0x07 };
    static const char SYS_ERRO_PACOTE_NAO_SUPORTADO[2] = { 0x55, 0x08 };
    //---------------------------------------------------------------
    // APP
    //---------------------------------------------------------------
    static const char DATA_HORA_ENVIO[2] =               { 0x00, 0x01 };    //<-recebe uma das respostas acima      
    static const char DATA_HORA_REQUISICAO[2] =          { 0x00, 0x02 };    //<-recebe uma resposta especifica, ou um dos erros
    static const char DATA_HORA_RESPOSTA[2] =            { 0x00, 0x03 };
    //---------------------------------------------------------------
    

    //200ms de timeout caso esteja ocupado
    if (!idle && xTaskGetTickCount() >= (ticks+(200/portTICK_PERIOD_MS)))
    {
        ESP_LOGI(TAG, "erro de timeout...");
        uart_write_bytes(0, &SYS_ERRO_TIMEOUT, 2); //resposta
        goto reseta_vars;
    }

    //para cada byte recebido...
    while (uart_read_bytes(0, &currentByteRead, 1, 0)) 
    {
        ticks = xTaskGetTickCount(); //le contador de ticks para cada byte lido

        //requisicao de livre? responde que esta livre.
        if (idle == true) 
        {
            sys_req[0] = previousByteRead;
            sys_req[1] = currentByteRead;    
             
            //requisicao de sistema - consulta de estado
            if (!strncmp( &sys_req, &SYS_CONSULTA_ESTADO, 2))
            {
                ESP_LOGI(TAG, "pronto...");
                uart_write_bytes(0, &SYS_RESPOSTA_ESTADO_PRONTO, 2); //resposta
                idle = false;       //ocupado
                in_i = 0;           //zera indice do buffer de entrada
                continue;           //reinicia loop while para ele rodar a proxima iteracao
            }
        }

        //esta ocupado?
        else 
        {
            static uint16_t tipo_de_pacote[2];
            static uint16_t size;
            static uint16_t data_bytes_received;
            static uint32_t checksum_calculado;
            static uint32_t checksum_recebido;
            static uint8_t step;

            //estouro no buffer de recepcao?
            if (in_i >= UART_BUFF_SIZE) 
            { 
                ESP_LOGI(TAG, "erro de tamanho maximo...");
                uart_write_bytes(0, &SYS_ERRO_TAMANHO, 2); //resposta
                goto reseta_vars;   
            }

            //etapa de sincronizacao
            if (!sincronizacao_recebida) 
            {
                sys_req[0] = previousByteRead;
                sys_req[1] = currentByteRead;

                if (!strncmp(&sys_req, &SYS_SINCRONIZACAO, 2)) 
                {
                    sincronizacao_recebida = true;
                    checksum_calculado = 0x55+0x01;
                    in_i = 0;
                    step = 1;
                    ESP_LOGI(TAG, "sincronizou...");
                }
            }

            //ou as etapas de recebimento do pacote
            else 
            {
                buff_in[in_i] = currentByteRead;

                //info de tamanho do pacote
                if (step == 1) 
                {
                    checksum_calculado += currentByteRead;

                    if (in_i == 0)      
                    { 
                        size = currentByteRead << 8;
                    } 

                    else if (in_i == 1) 
                    {  
                        size += currentByteRead; 
                        data_bytes_received = 0; 
                        step = 2;

                        ESP_LOGI(TAG, "tamanho = %d...", size);
                        
                        if (size < 4 || size > UART_BUFF_SIZE)
                        {
                            ESP_LOGI(TAG, "erro de tamanho...");
                            uart_write_bytes(0, &SYS_ERRO_TAMANHO, 2); //resposta de erro
                            goto reseta_vars;   
                        }

                    }  
                }

                //info de tipo de pacote
                else if (step == 2) 
                {
                    checksum_calculado += currentByteRead;

                    if (in_i == 2) 
                    { 
                        tipo_de_pacote[0] = currentByteRead; 
                    }

                    if (in_i == 3) 
                    { 
                        tipo_de_pacote[1] = currentByteRead;
                        data_bytes_received = 0;    //zera
                        size -= 2;  //os bytes de 'tipo' serao inutilizados no buffer, pois indice voltara para 0
                        in_i = 0;   //zera, para os bytes de dados serem colocados a partir do indice 0 e nao a partir do 4
                        step = 3;

                        if (tipo_de_pacote > SISTEMA_PACOTE_MAX || tipo_de_pacote == 0x0000) 
                        {
                            ESP_LOGI(TAG, "erro pacote nao suportado");
                            uart_write_bytes(0, &SYS_ERRO_PACOTE_NAO_SUPORTADO, 2); //resposta de erro 
                        }
                    }
                }

                //bytes de dados ou checksum
                else if (step == 3) 
                {
                    data_bytes_received++;

                    //bytes de dados
                    if (data_bytes_received <= size-2) 
                    {
                        buff_in[in_i] = currentByteRead;
                        checksum_calculado += currentByteRead; 
                    }

                    //recebe bytes de checksum, eh final de pacote
                    else 
                    {
                        //primeiro byte do checksum recebido?
                        if (checksum_byte_num == 1) 
                        {
                            checksum_recebido = currentByteRead << 8;
                            checksum_byte_num = 2;
                        }

                        //segundo byte do checksum recebido?
                        else if (checksum_byte_num == 2) 
                        {
                            checksum_recebido += currentByteRead; 

                            //checksum correto? analisa pacote e da um retorno
                            if (checksum_recebido == checksum_calculado) 
                            {
                                    //TRATA REQUISICOES INDIVIDUAIS AQUI     

                                    //esses pacotes abaixo possuem um tempo de processamento muito pequeno
                                    //e resposta pode ser dada aqui nesse ponto.

                                    if (!strncmp(&tipo_de_pacote, &DATA_HORA_ENVIO, 2) ||
                                        !strncmp(&tipo_de_pacote, &DATA_HORA_RESPOSTA, 2) ) 
                                    {
        
                                        ESP_LOGI(TAG, "data/hora recebidos...");
                                        uart_write_bytes(0, &SYS_CONFIRMA_RECEPCAO, 2); //resposta de "recebido"
                                    }
                            }

                            //checksum invalido?
                            else 
                            {
                                ESP_LOGI(TAG, "checksum incorreto..."); 
                                uart_write_bytes(0, &SYS_ERRO_CHECKSUM, 2); //resposta de erro
                            }

                            //reseta variaveis e volta para idle
                            goto reseta_vars;
                        }
                    }
                }
                in_i++;
            }
        }
        previousByteRead = currentByteRead;    
    }

    return;

    reseta_vars:
    sincronizacao_recebida = false;
    checksum_byte_num = 1;
    idle = true;
}
//-----------------------------------------------------------------------------