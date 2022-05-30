using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;
using Opc.Ua;
using Opc.Ua.Client;
using UAClientHelper;

namespace UA_Client
{
    public partial class UAClientForm : Form
    {
        /// <summary>
        /// Fields
        /// </summary>
        #region Fields
        private Session mySession;
        private UAClientHelperAPI myClientHelperAPI;
        private EndpointDescription mySelectedEndpoint;
        private ReferenceDescriptionCollection myReferenceDescriptionCollection;
        private UAClientCertForm myCertForm;
        #endregion

        /// <summary>
        /// Form Construction
        /// </summary>
        #region Construction
        public UAClientForm()
        {
            InitializeComponent();
            myClientHelperAPI = new UAClientHelperAPI();
            browsePage.Enabled = false;
            rwPage.Enabled = false;

            udCommandPriority1.SelectedIndex = 0;
            udCommandPriority2.SelectedIndex = 0;
            udCommandPriority3.SelectedIndex = 0;
            udCommandPriority4.SelectedIndex = 0;

            AddToLog("Applicazione avviata", false);
        }
        #endregion

        /// <summary>
        /// Event handlers called by the UI
        /// </summary>,
        #region UserInteractionHandlers
        private void EndpointButton_Click(object sender, EventArgs e)
        {
            bool foundEndpoints = false;
            lvwEndPoint.Items.Clear();
            //The local discovery URL for the discovery server
            string discoveryUrl = txtDiscovery.Text;
            try
            {
                ApplicationDescriptionCollection servers = myClientHelperAPI.FindServers(discoveryUrl);
                foreach (ApplicationDescription ad in servers)
                {
                    foreach (string url in ad.DiscoveryUrls)
                    {

                        try
                        {
                            EndpointDescriptionCollection endpoints = myClientHelperAPI.GetEndpoints(url);
                            foundEndpoints = foundEndpoints || endpoints.Count > 0;
                            foreach (EndpointDescription ep in endpoints)
                            {
                                string securityPolicy = ep.SecurityPolicyUri.Remove(0, 42);
                                string key = "[" + ad.ApplicationName + "] " + " [" + ep.SecurityMode + "] " + " [" + securityPolicy + "] " + " [" + ep.EndpointUrl + "]";
                                if (!lvwEndPoint.Items.ContainsKey(key))
                                {
                                    lvwEndPoint.Items.Add(key, key, 0).Tag = ep;
                                }

                            }
                        } catch (ServiceResultException sre) {
                            //If an url in ad.DiscoveryUrls can not be reached, myClientHelperAPI will throw an Exception
                            AddToLog(sre.Message, true);
                        }

                    }
                    if (!foundEndpoints) {
                        AddToLog("EndPoints non trovati", true);
                    }
                }
            } catch (Exception ex) {
                AddToLog(ex.Message, true);
            }
        }

        private void EpConnectButton_Click(object sender, EventArgs e)
        {
            //Check if sessions exists; If yes > delete subscriptions and disconnect
            if (mySession != null && !mySession.Disposed)
            {
                myClientHelperAPI.Disconnect();
                mySession = myClientHelperAPI.Session;

                ResetUI();
            }
            else
            {
                try
                {
                    //Register mandatory events (cert and keep alive)
                    myClientHelperAPI.KeepAliveNotification += new KeepAliveEventHandler(Notification_KeepAlive);
                    myClientHelperAPI.CertificateValidationNotification += new CertificateValidationEventHandler(Notification_ServerCertificate);

                    //Check for a selected endpoint
                    if (mySelectedEndpoint != null)
                    {
                        //Call connect
                        myClientHelperAPI.Connect(mySelectedEndpoint, userPwButton.Checked, userTextBox.Text, pwTextBox.Text).Wait();
                        //Extract the session object for further direct session interactions
                        mySession = myClientHelperAPI.Session;

                        //UI settings
                        epConnectServerButton.Text = "Disconnect from server";
                        browsePage.Enabled = true;
                        rwPage.Enabled = true;
                        myCertForm = null;
                    }
                    else
                    {
                        AddToLog("Selezionare un EndPoint prima di proseguire", true);
                        return;
                    }
                }
                catch (Exception ex)
                {
                    myCertForm = null;
                    ResetUI();
                    AddToLog(ex.InnerException.Message, true);
                }
            }

        }
        private void WriteValButton_Click(object sender, EventArgs e)
        {
            List<String> values = new List<string>();
            List<String> nodeIdStrings = new List<string>();

            values.Add(writeTextBox.Text);

            nodeIdStrings.Add(writeIdTextBox.Text);
            try {
                myClientHelperAPI.WriteValues(values, nodeIdStrings);
            } catch (Exception ex) {
                AddToLog(ex.Message, true);
            }
        }
        private void NodeTreeView_BeforeSelect(object sender, TreeViewCancelEventArgs e)
        {
            descriptionGridView.Rows.Clear();

            try
            {
                ReferenceDescription refDesc = (ReferenceDescription)e.Node.Tag;
                Node node = myClientHelperAPI.ReadNode(refDesc.NodeId.ToString());
                VariableNode variableNode = new VariableNode();

                string[] row1 = new string[] { "Node Id", refDesc.NodeId.ToString() };
                string[] row2 = new string[] { "Namespace Index", refDesc.NodeId.NamespaceIndex.ToString() };
                string[] row3 = new string[] { "Identifier Type", refDesc.NodeId.IdType.ToString() };
                string[] row4 = new string[] { "Identifier", refDesc.NodeId.Identifier.ToString() };
                string[] row5 = new string[] { "Browse Name", refDesc.BrowseName.ToString() };
                string[] row6 = new string[] { "Display Name", refDesc.DisplayName.ToString() };
                string[] row7 = new string[] { "Node Class", refDesc.NodeClass.ToString() };
                string[] row8 = new string[] { "Description", "null" };
                try { row8 = new string[] { "Description", node.Description.ToString() }; }
                catch { row8 = new string[] { "Description", "null" }; }
                string[] row9 = new string[] { "Type Definition", refDesc.TypeDefinition.ToString() };
                string[] row10 = new string[] { "Write Mask", node.WriteMask.ToString() };
                string[] row11 = new string[] { "User Write Mask", node.UserWriteMask.ToString() };
                if (node.NodeClass == NodeClass.Variable)
                {
                    variableNode = (VariableNode)node.DataLock;
                    List<NodeId> nodeIds = new List<NodeId>();
                    List<string> displayNames = new List<string>();
                    List<ServiceResult> errors = new List<ServiceResult>();
                    NodeId nodeId = new NodeId(variableNode.DataType);
                    nodeIds.Add(nodeId);
                    mySession.ReadDisplayName(nodeIds, out displayNames, out errors);

                    string[] row12 = new string[] { "Data Type", displayNames[0] };
                    string[] row13 = new string[] { "Value Rank", variableNode.ValueRank.ToString() };
                    string[] row14 = new string[] { "Array Dimensions", variableNode.ArrayDimensions.Capacity.ToString() };
                    string[] row15 = new string[] { "Access Level", variableNode.AccessLevel.ToString() };
                    string[] row16 = new string[] { "Minimum Sampling Interval", variableNode.MinimumSamplingInterval.ToString() };
                    string[] row17 = new string[] { "Historizing", variableNode.Historizing.ToString() };

                    object[] rows = new object[] { row1, row2, row3, row4, row5, row6, row7, row8, row9, row10, row11, row12, row13, row14, row15, row16, row17 };
                    foreach (string[] rowArray in rows)
                    {
                        descriptionGridView.Rows.Add(rowArray);
                    }
                }
                else
                {
                    object[] rows = new object[] { row1, row2, row3, row4, row5, row6, row7, row8, row9, row10, row11 };
                    foreach (string[] rowArray in rows)
                    {
                        descriptionGridView.Rows.Add(rowArray);
                    }
                }

                descriptionGridView.ClearSelection();
            } catch (Exception ex) {
                AddToLog(ex.Message, true);
            }

        }
        private void ClientForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            try
            {
                myClientHelperAPI.Disconnect();
            }
            catch
            {
                ;
            }
        }
        private void NodeTreeView_BeforeExpand(object sender, TreeViewCancelEventArgs e)
        {
            e.Node.Nodes.Clear();

            ReferenceDescriptionCollection referenceDescriptionCollection;
            ReferenceDescription refDesc = (ReferenceDescription)e.Node.Tag;

            try {
                referenceDescriptionCollection = myClientHelperAPI.BrowseNode(refDesc);
            } catch (Exception ex) {
                AddToLog(ex.Message, true);
                return;
            }

            foreach (ReferenceDescription tempRefDesc in referenceDescriptionCollection)
            {
                if (tempRefDesc.ReferenceTypeId != ReferenceTypeIds.HasNotifier)
                {
                    e.Node.Nodes.Add(tempRefDesc.DisplayName.ToString()).Tag = tempRefDesc;
                }
            }
            foreach (TreeNode node in e.Node.Nodes)
            {
                node.Nodes.Add("");
            }
        }
        private void BrowsePage_Enter(object sender, EventArgs e)
        {
            if (myReferenceDescriptionCollection == null)
            {
                try
                {
                    myReferenceDescriptionCollection = myClientHelperAPI.BrowseRoot();
                    foreach (ReferenceDescription refDesc in myReferenceDescriptionCollection)
                    {
                        nodeTreeView.Nodes.Add(refDesc.DisplayName.ToString()).Tag = refDesc;
                        foreach (TreeNode node in nodeTreeView.Nodes)
                        {
                            node.Nodes.Add("");
                        }
                    }
                } catch (Exception ex) {
                    AddToLog(ex.Message, true);
                }
            }
        }
        private void ReadValButton_Click(object sender, EventArgs e)
        {
            List<String> nodeIdStrings = new List<String>();
            List<String> values = new List<String>();
            nodeIdStrings.Add(readIdTextBox.Text);
            try {
                values = myClientHelperAPI.ReadValues(nodeIdStrings);
                readTextBox.Text = values.ElementAt<String>(0);
            } catch (Exception ex) {
                AddToLog(ex.Message, true);
            }

        }
        private void EndpointListView_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            mySelectedEndpoint = (EndpointDescription)e.Item.Tag;
        }
        private void OpcTabControl_Selecting(object sender, TabControlCancelEventArgs e)
        {
            e.Cancel = !e.TabPage.Enabled;
            if (!e.TabPage.Enabled) {
                AddToLog("Stabilire dapprima la connessione col PLC.", true);
            }
        }

        private void UserPwButton_CheckedChanged(object sender, EventArgs e)
        {
            if (userPwButton.Checked)
            {
                userTextBox.Enabled = true;
                pwTextBox.Enabled = true;
            }
        }
        private void UserAnonButton_CheckedChanged(object sender, EventArgs e)
        {
            if (userAnonButton.Checked)
            {
                userTextBox.Enabled = false;
                pwTextBox.Enabled = false;
            }
        }

        private void DiscoveryTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                EndpointButton_Click(this, new EventArgs());
            }
        }
        #endregion

        /// <summary>
        /// Global OPC UA event handlers
        /// </summary>
        #region OpcEventHandlers
        private void Notification_ServerCertificate(CertificateValidator cert, CertificateValidationEventArgs e)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new CertificateValidationEventHandler(Notification_ServerCertificate), cert, e);
                return;
            }

            try
            {
                //Search for the server's certificate in store; if found -> accept
                X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);
                X509CertificateCollection certCol = store.Certificates.Find(X509FindType.FindByThumbprint, e.Certificate.Thumbprint, true);
                store.Close();
                if (certCol.Capacity > 0)
                {
                    e.Accept = true;
                }

                //Show cert dialog if cert hasn't been accepted yet
                else
                {
                    if (!e.Accept & myCertForm == null)
                    {
                        myCertForm = new UAClientCertForm(e);
                        myCertForm.ShowDialog();
                    }
                }
            }
            catch
            {
                ;
            }
        }

        private void Notification_KeepAlive(Session sender, KeepAliveEventArgs e)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new KeepAliveEventHandler(Notification_KeepAlive), sender, e);
                return;
            }

            try
            {
                // check for events from discarded sessions.
                if (!Object.ReferenceEquals(sender, mySession))
                {
                    return;
                }

                // check for disconnected session.
                if (!ServiceResult.IsGood(e.Status))
                {
                    // try reconnecting using the existing session state
                    mySession.Reconnect();
                }
            } catch (Exception ex) {
                AddToLog(ex.Message, true);
                ResetUI();
            }
        }
        #endregion

        /// <summary>
        /// Private methods for UI handling
        /// </summary>
        #region PrivateMethods
        private void ResetUI()
        {
            descriptionGridView.Rows.Clear();
            nodeTreeView.Nodes.Clear();
            myReferenceDescriptionCollection = null;

            readIdTextBox.Text = string.Empty;
            writeIdTextBox.Text = string.Empty;
            readTextBox.Text = string.Empty;
            writeTextBox.Text = string.Empty;
            epConnectServerButton.Text = "Connect to server";

            browsePage.Enabled = false;
            rwPage.Enabled = false;

            opcTabControl.SelectedIndex = 0;
        }
        #endregion

        #region Customized logic ...

        private bool bFirstStart = true;
        private byte bytHello = 0;
        private int nCountHB = 0;

        private void tmrMain_Tick(object sender, EventArgs e)
        {
            (sender as Timer).Enabled = false;

            List<String> values = new List<String>();
            List<String> nodeIdStrings = new List<String>();

            if (opcTabControl.SelectedTab == opcTabControl.TabPages["rwPage"]) {

                if (bFirstStart) {
                    bFirstStart = false;
                    bytHello = 0;

                }

                if (nCountHB == 33 || nCountHB == 66) {
                    labHB.Visible = !labHB.Visible;

                    // --------------------- ROBOTS: aggiornamento Stati ...
                    for (int i = 1; i < 5; i++)
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfStati_M[" + i.ToString() + "].WDG_STATUS"));

                    try {
                        values = myClientHelperAPI.ReadValues(nodeIdStrings);

                        labStatusRobot1.Text = getStatus(Convert.ToInt32(values[0]));
                        labStatusRobot2.Text = getStatus(Convert.ToInt32(values[1]));
                        labStatusRobot3.Text = getStatus(Convert.ToInt32(values[2]));
                        labStatusRobot4.Text = getStatus(Convert.ToInt32(values[3]));


                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }

                    #region Aggiornamento della risposta alle risposte OK e ERRROR ...

                    if (labAnswerRobot1.Text.Contains("OK") || labAnswerRobot1.Text.Contains("ERROR")) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[1].CMD_RESULT");
                        values.Add("0");

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset status for Robot #1.", false);
                    }

                    if (labAnswerRobot2.Text.Contains("OK") || labAnswerRobot2.Text.Contains("ERROR")) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[2].CMD_RESULT");
                        values.Add("0");

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset status for Robot #2.", false);
                    }

                    if (labAnswerRobot3.Text.Contains("OK") || labAnswerRobot3.Text.Contains("ERROR")) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[3].CMD_RESULT");
                        values.Add("0");

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset status for Robot #3.", false);
                    }

                    if (labAnswerRobot4.Text.Contains("OK") || labAnswerRobot4.Text.Contains("ERROR")) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[4].CMD_RESULT");
                        values.Add("0");

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset status for Robot #4.", false);
                    }

                    #endregion

                    // --------------------- Aggiornamento Risposte ...
                    for (int i = 1; i < 5; i++)
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfStati_M[", i.ToString(), "].CMD_RESULT"));

                    try {
                        values = myClientHelperAPI.ReadValues(nodeIdStrings);

                        labAnswerRobot1.Text = getResult(Convert.ToInt32(values[0]));
                        labAnswerRobot2.Text = getResult(Convert.ToInt32(values[1]));
                        labAnswerRobot3.Text = getResult(Convert.ToInt32(values[2]));
                        labAnswerRobot4.Text = getResult(Convert.ToInt32(values[3]));
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }

                    // --------------------- Aggiornamento Executing (il PLC ripete il codice comando impartito) ...
                    for (int i = 1; i < 5; i++)
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfStati_M[" + i.ToString() + "].CMD_EXECUTING"));

                    try {
                        values = myClientHelperAPI.ReadValues(nodeIdStrings);

                        labExcRobot1.Text = values[0];
                        labExcRobot2.Text = values[1];
                        labExcRobot3.Text = values[2];
                        labExcRobot4.Text = values[3];
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }

                    // --------------------- ISOLA: aggiornamento Stato ...
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.GENERAL_STATUS");

                    try {
                        values = myClientHelperAPI.ReadValues(nodeIdStrings);

                        labAreaStatus.Text = getGeneralStatus(Convert.ToInt32(values[0]));
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }

                    #region Special Data Management (LOADING) ...

                    if (nOpenPage != 0) {

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].TRAY_LR"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].TRAY_RESULT"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].MOTOR_DIRECTION"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].MOTOR_SPEED"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].MOTOR_ACC"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].MOTOR_MAX_TORQUE"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].HUB"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].WEIGHT_HEIGHT"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].WEIGHT_SPEED"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].FORK_COMMAND"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].UNSCREW_TIMEOUT"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].SHOW_ERROR"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].SHOW_LIGHT_TOWER"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].TIMEOUT_1"));
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nOpenPage.ToString(), "].TIMEOUT_2"));

                        try {
                            values = myClientHelperAPI.ReadValues(nodeIdStrings);

                            fSpecialData.udTrayLR.SelectedIndex = Convert.ToInt32(values[0]);
                            fSpecialData.udTrayResult.SelectedIndex = Convert.ToInt32(values[1]);
                            fSpecialData.udMotorDirection.SelectedIndex = Convert.ToInt32(values[2]);

                            fSpecialData.numMotorSpeed.Value = Convert.ToInt32(values[3]);
                            fSpecialData.numMotorAcc.Value = Convert.ToInt32(values[4]);
                            fSpecialData.numMotorMaxTorque.Value = Convert.ToInt32(values[5]);

                            fSpecialData.udHub.SelectedIndex = Convert.ToInt32(values[6]);

                            fSpecialData.numWeightHeight.Value = Convert.ToInt32(values[7]);
                            fSpecialData.numWeightSpeed.Value = Convert.ToInt32(values[8]);

                            fSpecialData.udForkCommand.SelectedIndex = Convert.ToInt32(values[9]);

                            fSpecialData.numUnscrewTimeout.Value = Convert.ToInt32(values[10]);

                            fSpecialData.txtShowError.Text = values[11].ToString();

                            string[] _supp = values[12].Split(new char[] { ';' });

                            fSpecialData.chk00.Checked = _supp[0].ToUpper().Equals("TRUE");
                            fSpecialData.chk01.Checked = _supp[1].ToUpper().Equals("TRUE");
                            fSpecialData.chk02.Checked = _supp[2].ToUpper().Equals("TRUE");
                            fSpecialData.chk03.Checked = _supp[3].ToUpper().Equals("TRUE");
                            fSpecialData.chk04.Checked = _supp[4].ToUpper().Equals("TRUE");
                            fSpecialData.chk05.Checked = _supp[5].ToUpper().Equals("TRUE");
                            fSpecialData.chk06.Checked = _supp[6].ToUpper().Equals("TRUE");
                            fSpecialData.chk07.Checked = _supp[7].ToUpper().Equals("TRUE");
                            fSpecialData.chk08.Checked = _supp[8].ToUpper().Equals("TRUE");
                            fSpecialData.chk09.Checked = _supp[9].ToUpper().Equals("TRUE");
                            fSpecialData.chk10.Checked = _supp[10].ToUpper().Equals("TRUE");
                            fSpecialData.chk11.Checked = _supp[11].ToUpper().Equals("TRUE");
                            fSpecialData.chk12.Checked = _supp[12].ToUpper().Equals("TRUE");
                            fSpecialData.chk13.Checked = _supp[13].ToUpper().Equals("TRUE");
                            fSpecialData.chk14.Checked = _supp[14].ToUpper().Equals("TRUE");
                            fSpecialData.chk15.Checked = _supp[15].ToUpper().Equals("TRUE");

                            fSpecialData.numTimeout1.Value = Convert.ToInt32(values[13]);
                            fSpecialData.numTimeout2.Value = Convert.ToInt32(values[14]);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        nOpenPage = 0;
                    }

                    #endregion

                    #region Special Data Management (SAVING) ...

                    if (nSavePage != 0) {
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].TRAY_LR"));
                        values.Add(fSpecialData.udTrayLR.SelectedIndex.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].TRAY_RESULT"));
                        values.Add(fSpecialData.udTrayResult.SelectedIndex.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].MOTOR_DIRECTION"));
                        values.Add(fSpecialData.udMotorDirection.SelectedIndex.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].MOTOR_SPEED"));
                        values.Add(fSpecialData.numMotorSpeed.Value.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].MOTOR_ACC"));
                        values.Add(fSpecialData.numMotorAcc.Value.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].MOTOR_MAX_TORQUE"));
                        values.Add(fSpecialData.numMotorMaxTorque.Value.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].HUB"));
                        values.Add(fSpecialData.udHub.SelectedIndex.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].WEIGHT_HEIGHT"));
                        values.Add(fSpecialData.numWeightHeight.Value.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].WEIGHT_SPEED"));
                        values.Add(fSpecialData.numWeightSpeed.Value.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].FORK_COMMAND"));
                        values.Add(fSpecialData.udForkCommand.SelectedIndex.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].UNSCREW_TIMEOUT"));
                        values.Add(fSpecialData.numUnscrewTimeout.Value.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].SHOW_ERROR"));
                        values.Add(fSpecialData.txtShowError.Text);

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].SHOW_LIGHT_TOWER"));
                        string _supp = string.Concat(
                            fSpecialData.chk00.Checked ? "True" : "False", ";",
                            fSpecialData.chk01.Checked ? "True" : "False", ";",
                            fSpecialData.chk02.Checked ? "True" : "False", ";",
                            fSpecialData.chk03.Checked ? "True" : "False", ";",
                            fSpecialData.chk04.Checked ? "True" : "False", ";",
                            fSpecialData.chk05.Checked ? "True" : "False", ";",
                            fSpecialData.chk06.Checked ? "True" : "False", ";",
                            fSpecialData.chk07.Checked ? "True" : "False", ";",
                            fSpecialData.chk08.Checked ? "True" : "False", ";",
                            fSpecialData.chk09.Checked ? "True" : "False", ";",
                            fSpecialData.chk10.Checked ? "True" : "False", ";",
                            fSpecialData.chk11.Checked ? "True" : "False", ";",
                            fSpecialData.chk12.Checked ? "True" : "False", ";",
                            fSpecialData.chk13.Checked ? "True" : "False", ";",
                            fSpecialData.chk14.Checked ? "True" : "False", ";",
                            fSpecialData.chk15.Checked ? "True" : "False"
                            );
                        values.Add(_supp);

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].TIMEOUT_1"));
                        values.Add(fSpecialData.numTimeout1.Value.ToString());

                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfParam_M[", nSavePage.ToString(), "].TIMEOUT_2"));
                        values.Add(fSpecialData.numTimeout2.Value.ToString());

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Data saved on PLC sucessfully.", false);

                        fSpecialData.Close();
                        fSpecialData.Dispose(); fSpecialData = null;

                        nSavePage = 0;
                    }

                    #endregion
                }

                if (nCountHB++ >= 66) {
                    nCountHB = 0;

                    // --------------------- Gestione HELLO ...
                    labHello.Text = bytHello.ToString();

                    bytHello = bytHello == 255 ? (byte)0 : Convert.ToByte(bytHello + 1);

                    for (int i = 1; i < 5; i++) {
                        values.Add(bytHello.ToString());
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfStati_M[", i.ToString(), "].WDG_HELLO"));
                    }

                    try {
                        myClientHelperAPI.WriteValues(values, nodeIdStrings);
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }

                    // --------------------- ROBOT 1-4: lettura ALLARMI  ...

                    for (int i = 1; i < 5; i++)
                        nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfStati_M[" , i.ToString(), "].ERRORS"));

                    try {
                        values = myClientHelperAPI.ReadValues(nodeIdStrings);

                        setRobAlrms1(values[0].ToString().Split(new char[] { ';' }));
                        setRobAlrms2(values[1].ToString().Split(new char[] { ';' }));
                        setRobAlrms3(values[2].ToString().Split(new char[] { ';' }));
                        setRobAlrms4(values[3].ToString().Split(new char[] { ';' }));


                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }

                    // --------------------- ISOLA: lettura ALLARMI ...

                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.GENERAL_ERRORS");

                    try {
                        values = myClientHelperAPI.ReadValues(nodeIdStrings);

                        setAreaAlrms(values[0].ToString().Split(new char[] { ';' }));
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }

                    // --------------------- Scrittura ACK ROBOT 1-4 ...

                    if (!string.IsNullOrEmpty(asRobotsResetAlr[0])) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[1].RESET_ERRORS");
                        values.Add(asRobotsResetAlr[0]);
                        asRobotsResetAlr[0] = string.Empty;

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset allarme robot 1 eseguito!", false);
                    }

                    if (!string.IsNullOrEmpty(asRobotsResetAlr[1])) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[2].RESET_ERRORS");
                        values.Add(asRobotsResetAlr[1]);
                        asRobotsResetAlr[1] = string.Empty;

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset allarme robot 2 eseguito!", false);
                    }

                    if (!string.IsNullOrEmpty(asRobotsResetAlr[2])) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[3].RESET_ERRORS");
                        values.Add(asRobotsResetAlr[2]);
                        asRobotsResetAlr[2] = string.Empty;

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset allarme robot 3 eseguito!", false);
                    }

                    if (!string.IsNullOrEmpty(asRobotsResetAlr[3])) {
                        nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[4].RESET_ERRORS");
                        values.Add(asRobotsResetAlr[3]);
                        asRobotsResetAlr[3] = string.Empty;

                        try {
                            myClientHelperAPI.WriteValues(values, nodeIdStrings);
                        } catch (Exception ex) {
                            AddToLog(ex.Message, true);
                        } finally {
                            nodeIdStrings.Clear();
                            values.Clear();
                        }

                        AddToLog("Reset allarme robot 4 eseguito!", false);
                    }
                }

                // --------------------- Aggiornamento Velocità Angolare Corrente (1/100 RPM) ...
                for (int i = 1; i < 5; i++)
                    nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfStati_M[", i.ToString(), "].MOTOR_CURR_SPEED"));

                try {
                    values = myClientHelperAPI.ReadValues(nodeIdStrings);

                    labAngSpeed1.Text = values[0];
                    labAngSpeed2.Text = values[1];
                    labAngSpeed3.Text = values[2];
                    labAngSpeed4.Text = values[3];
                } catch (Exception ex) {
                    AddToLog(ex.Message, true);
                } finally {
                    nodeIdStrings.Clear();
                    values.Clear();
                }

                // --------------------- Aggiornamento Coppia Corrente (1/100 Nm) ...

                for (int i = 1; i < 5; i++)
                    nodeIdStrings.Add(string.Concat("ns=2;s=Application.Interfaccia_PC.ItfStati_M[", i.ToString(), "].MOTOR_CURR_TORQUE"));

                try {
                    values = myClientHelperAPI.ReadValues(nodeIdStrings);

                    labTorque1.Text = values[0];
                    labTorque2.Text = values[1];
                    labTorque3.Text = values[2];
                    labTorque4.Text = values[3];
                } catch (Exception ex) {
                    AddToLog(ex.Message, true);
                } finally {
                    nodeIdStrings.Clear();
                    values.Clear();
                }

                // --------------------- Gestione comandi ...

                if (abCommandsToSubmit[0]) {
                    abCommandsToSubmit[0] = false;

                    // Priority ...
                    values.Add(udCommandPriority1.SelectedIndex.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[1].CMD_PRIORITY");

                    // Command ...
                    values.Add(udCommandCode1.Value.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[1].COMMAND");

                    try {
                        myClientHelperAPI.WriteValues(values, nodeIdStrings);
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }
                }

                if (abCommandsToSubmit[1]) {
                    abCommandsToSubmit[1] = false;

                    // Priority ...
                    values.Add(udCommandPriority2.SelectedIndex.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[2].CMD_PRIORITY");

                    // Command ...
                    values.Add(udCommandCode2.Value.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[2].COMMAND");

                    try {
                        myClientHelperAPI.WriteValues(values, nodeIdStrings);
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }
                }

                if (abCommandsToSubmit[2]) {
                    abCommandsToSubmit[2] = false;

                    // Priority ...
                    values.Add(udCommandPriority3.SelectedIndex.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[3].CMD_PRIORITY");

                    // Command ...
                    values.Add(udCommandCode3.Value.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[3].COMMAND");

                    try {
                        myClientHelperAPI.WriteValues(values, nodeIdStrings);
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }
                }

                if (abCommandsToSubmit[3]) {
                    abCommandsToSubmit[3] = false;

                    // Priority ...
                    values.Add(udCommandPriority4.SelectedIndex.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[4].CMD_PRIORITY");

                    // Command ...
                    values.Add(udCommandCode4.Value.ToString());
                    nodeIdStrings.Add("ns=2;s=Application.Interfaccia_PC.ItfStati_M[4].COMMAND");

                    try {
                        myClientHelperAPI.WriteValues(values, nodeIdStrings);
                    } catch (Exception ex) {
                        AddToLog(ex.Message, true);
                    } finally {
                        nodeIdStrings.Clear();
                        values.Clear();
                    }
                }
            }

            (sender as Timer).Enabled = true;
        }

        #region Robots errors management ...

        private string[] asRobotsResetAlr = new string[4];

        private void cmdRob1_Click(object sender, EventArgs e) {
            int nErrNr = Convert.ToInt32((sender as Button).Name.Substring((sender as Button).Name.Length - 2, 2));

            if (MessageBox.Show(this, string.Concat("Confermare l'acknowledgement dell'allarme #", nErrNr.ToString(), "?"), 
                "ROBOT #1 ...", 
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button1) == DialogResult.Yes) {
                nErrNr--;
                asRobotsResetAlr[0] = string.Empty;

                for (int i = 0; i < 51; i++) {
                    if (i == nErrNr)
                        asRobotsResetAlr[0] += "True;";
                    else
                        asRobotsResetAlr[0] += "False;";
                }

                asRobotsResetAlr[0] = asRobotsResetAlr[0].TrimEnd(new char[]{';'});
                AddToLog(asRobotsResetAlr[0], false);
            }
        }

        private void cmdRob2_Click(object sender, EventArgs e) {
            int nErrNr = Convert.ToInt32((sender as Button).Name.Substring((sender as Button).Name.Length - 2, 2));

            if (MessageBox.Show(this, string.Concat("Confermare l'acknowledgement dell'allarme #", nErrNr.ToString(), "?"), 
                "ROBOT #2 ...", 
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button1) == DialogResult.Yes) {
                nErrNr--;
                asRobotsResetAlr[1] = string.Empty;

                for (int i = 0; i < 51; i++) {
                    if (i == nErrNr)
                        asRobotsResetAlr[1] += "True;";
                    else
                        asRobotsResetAlr[1] += "False;";
                }

                asRobotsResetAlr[1] = asRobotsResetAlr[1].TrimEnd(new char[] { ';' });
                AddToLog(asRobotsResetAlr[1], false);
            }
        }

        private void cmdRob3_Click(object sender, EventArgs e) {
            int nErrNr = Convert.ToInt32((sender as Button).Name.Substring((sender as Button).Name.Length - 2, 2));

            if (MessageBox.Show(this, string.Concat("Confermare l'acknowledgement dell'allarme #", nErrNr.ToString(), "?"),
                "ROBOT #3 ...",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button1) == DialogResult.Yes) {
                nErrNr--;
                asRobotsResetAlr[2] = string.Empty;

                for (int i = 0; i < 51; i++) {
                    if (i == nErrNr)
                        asRobotsResetAlr[2] += "True;";
                    else
                        asRobotsResetAlr[2] += "False;";
                }

                asRobotsResetAlr[2] = asRobotsResetAlr[2].TrimEnd(new char[] { ';' });
                AddToLog(asRobotsResetAlr[2], false);
            }
        }

        private void cmdRob4_Click(object sender, EventArgs e) {
            int nErrNr = Convert.ToInt32((sender as Button).Name.Substring((sender as Button).Name.Length - 2, 2));

            if (MessageBox.Show(this, string.Concat("Confermare l'acknowledgement dell'allarme #", nErrNr.ToString(), "?"),
                "ROBOT #4 ...",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button1) == DialogResult.Yes) {
                nErrNr--;
                asRobotsResetAlr[3] = string.Empty;

                for (int i = 0; i < 51; i++) {
                    if (i == nErrNr)
                        asRobotsResetAlr[3] += "True;";
                    else
                        asRobotsResetAlr[3] += "False;";
                }

                asRobotsResetAlr[3] = asRobotsResetAlr[3].TrimEnd(new char[] { ';' });
                AddToLog(asRobotsResetAlr[3], false);
            }
        }

        private void setAreaAlrms(string[] alrCfg)
        {
            panAreaAlr1.BackColor = alrCfg[0].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            panAreaAlr2.BackColor = alrCfg[1].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            panAreaAlr3.BackColor = alrCfg[2].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            panAreaAlr4.BackColor = alrCfg[3].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            panAreaAlr5.BackColor = alrCfg[4].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            panAreaAlr6.BackColor = alrCfg[5].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            panAreaAlr7.BackColor = alrCfg[6].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
        }
        private void setRobAlrms1(string[] alrCfg) {
            cmdRob1Err01.BackColor = alrCfg[0].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err02.BackColor = alrCfg[1].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err03.BackColor = alrCfg[2].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err04.BackColor = alrCfg[3].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err05.BackColor = alrCfg[4].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err06.BackColor = alrCfg[5].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err07.BackColor = alrCfg[6].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err08.BackColor = alrCfg[7].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err09.BackColor = alrCfg[8].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err10.BackColor = alrCfg[9].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err11.BackColor = alrCfg[10].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err12.BackColor = alrCfg[11].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob1Err13.BackColor = alrCfg[12].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
        }

        private void setRobAlrms2(string[] alrCfg) {
            cmdRob2Err01.BackColor = alrCfg[0].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err02.BackColor = alrCfg[1].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err03.BackColor = alrCfg[2].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err04.BackColor = alrCfg[3].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err05.BackColor = alrCfg[4].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err06.BackColor = alrCfg[5].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err07.BackColor = alrCfg[6].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err08.BackColor = alrCfg[7].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err09.BackColor = alrCfg[8].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err10.BackColor = alrCfg[9].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err11.BackColor = alrCfg[10].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err12.BackColor = alrCfg[11].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob2Err13.BackColor = alrCfg[12].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
        }

        private void setRobAlrms3(string[] alrCfg) {
            cmdRob3Err01.BackColor = alrCfg[0].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err02.BackColor = alrCfg[1].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err03.BackColor = alrCfg[2].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err04.BackColor = alrCfg[3].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err05.BackColor = alrCfg[4].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err06.BackColor = alrCfg[5].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err07.BackColor = alrCfg[6].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err08.BackColor = alrCfg[7].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err09.BackColor = alrCfg[8].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err10.BackColor = alrCfg[9].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err11.BackColor = alrCfg[10].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err12.BackColor = alrCfg[11].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob3Err13.BackColor = alrCfg[12].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
        }

        private void setRobAlrms4(string[] alrCfg) {
            cmdRob4Err01.BackColor = alrCfg[0].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err02.BackColor = alrCfg[1].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err03.BackColor = alrCfg[2].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err04.BackColor = alrCfg[3].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err05.BackColor = alrCfg[4].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err06.BackColor = alrCfg[5].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err07.BackColor = alrCfg[6].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err08.BackColor = alrCfg[7].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err09.BackColor = alrCfg[8].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err10.BackColor = alrCfg[9].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err11.BackColor = alrCfg[10].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err12.BackColor = alrCfg[11].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
            cmdRob4Err13.BackColor = alrCfg[12].ToUpper().Equals("FALSE") ? System.Drawing.Color.Navy : System.Drawing.Color.Red;
        }

        #endregion

        private string getStatus(int statCode) {
            string sRet = string.Empty;
            switch (statCode) {
                case 0:
                    sRet = "RESET (0)";
                    break;
                case 1:
                    sRet = "WORKING (1)";
                    break;
                case 2:
                    sRet = "ERROR-SOFT (2)";
                    break;
                case 3:
                    sRet = "ERROR-HARD (3)";
                    break;
                case 4:
                    sRet = "ERROR (4)";
                    break;
                default:
                    sRet = "(>4) UNKNOWN";
                    break;
            }


            return sRet;
        }

        private string getGeneralStatus(int statCode) {
            string sRet = string.Empty;
            switch (statCode) {
                case 0:
                    sRet = "STOPPED (0)";
                    break;
                case 1:
                    sRet = "STOP REQUESTED (1)";
                    break;
                case 2:
                    sRet = "SAFETY STOP REQUESTED (2)";
                    break;
                case 3:
                    sRet = "AUTO WORKING (3)";
                    break;
                case 4:
                    sRet = "MANUAL WORKING (4)";
                    break;
                case 5:
                    sRet = "ERROR (5)";
                    break;
                default:
                    sRet = "(>4) UNKNOWN";
                    break;
            }


            return sRet;
        }

        private string getResult(int statCode)
        {
            string sRet = string.Empty;
            switch (statCode)
            {
                case 0:
                    sRet = "IDLE (0)";
                    break;
                case 1:
                    sRet = "WAITING (1)";
                    break;
                case 2:
                    sRet = "WORKING (2)";
                    break;
                case 3:
                    sRet = "OK (3)";
                    break;
                case 4:
                    sRet = "ERROR (4)";
                    break;
                default:
                    sRet = "(>4) UNKNOWN";
                    break;
            }

            return sRet;
        }

        private void AddToLog(string EventDescription, bool IsError) {
            ListViewItem lviEventToLog = new ListViewItem(EventDescription, IsError ? 2 : 5);
            lviEventToLog.SubItems.Add(DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss"));

            if (lvwLog.Items.Count > 100)
                lvwLog.Items.Clear();

            lvwLog.Items.Add(lviEventToLog);

            lvwLog.Items[lvwLog.Items.Count - 1].EnsureVisible();
        }
        #endregion

        private void chkShowRealDump_CheckedChanged(object sender, EventArgs e)
        {

        }

        #region Commands to submit ...

        private bool[] abCommandsToSubmit = new bool[]{false,false,false,false};

        private void cmdSendCmd1_Click(object sender, EventArgs e)
        {
            abCommandsToSubmit[0] = true;
        }

        private void cmdSendCmd2_Click(object sender, EventArgs e)
        {
            abCommandsToSubmit[1] = true;
        }

        private void cmdSendCmd3_Click(object sender, EventArgs e)
        {
            abCommandsToSubmit[2] = true;
        }

        private void cmdSendCmd4_Click(object sender, EventArgs e)
        {
            abCommandsToSubmit[3] = true;
        }

        #endregion

        #region Special Data Management ...

        private frmSpecialData fSpecialData = null;
        private int nOpenPage = 0;
        private int nSavePage = 0;

        private void cmdSpecialDataRobot1_Click(object sender, EventArgs e) {
            nOpenPage = 1;

            fSpecialData = new frmSpecialData();

            // lettura dati form ...
            fSpecialData.Text = "Dati Speciali Robot 1";

            fSpecialData.ShowDialog(this);

            if (fSpecialData.DialogResult == DialogResult.OK) {
                // Salvataggio dati form ...

                nSavePage = 1;
            }

            //fSpecialData.Close();
            //fSpecialData.Dispose(); fSpecialData = null;
        }

        private void cmdSpecialDataRobot2_Click(object sender, EventArgs e) {
            nOpenPage = 2;

            fSpecialData = new frmSpecialData();

            // lettura dati form ...
            fSpecialData.Text = "Dati Speciali Robot 2";

            fSpecialData.ShowDialog(this);

            if (fSpecialData.DialogResult == DialogResult.OK)
            {
                // Salvataggio dati form ...
                nSavePage = 2;
            }
        }

        private void cmdSpecialDataRobot3_Click(object sender, EventArgs e) {
            nOpenPage = 3;

            fSpecialData = new frmSpecialData();

            // lettura dati form ...
            fSpecialData.Text = "Dati Speciali Robot 3";

            fSpecialData.ShowDialog(this);

            if (fSpecialData.DialogResult == DialogResult.OK)
            {
                // Salvataggio dati form ...
                nSavePage = 3;
            }
        }

        private void cmdSpecialDataRobot4_Click(object sender, EventArgs e) {
            nOpenPage = 4;

            fSpecialData = new frmSpecialData();

            // lettura dati form ...
            fSpecialData.Text = "Dati Speciali Robot 4";

            fSpecialData.ShowDialog(this);

            if (fSpecialData.DialogResult == DialogResult.OK)
            {
                // Salvataggio dati form ...
                nSavePage = 4;
            }
        }

        #endregion
    }
}