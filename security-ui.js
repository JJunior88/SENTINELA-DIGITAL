// Todos os dados vindos do Drive e do Windows são exibidos como texto.
let securityBusy = false;
let lastReport = '';
const dateLabel = value => {
  if (!value) return 'Não informado';
  const match = String(value).match(/^\/Date\((\d+)/);
  const d = new Date(match ? Number(match[1]) : value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString('pt-BR');
};

function renderSecurity(data) {
  $('#google-state').textContent = data.google_connected ? 'Conta conectada nesta execução.' : 'Não conectado ou autorização expirada.';
  $('#drive-scan').disabled = !data.google_connected || data.drive.status === 'running';
  $('#google-disconnect').disabled = !data.google_connected && data.drive.status === 'idle';
  $('#pc-scan').disabled = !data.windows || data.pc.status === 'running';
  $('#pc-status').disabled = !data.windows || data.pc.status === 'running';
  const serialized = JSON.stringify([data.drive, data.pc]);
  if (serialized === lastReport) return;
  lastReport = serialized;
  const drive = $('#drive-result');
  drive.replaceChildren();
  const report = data.drive;
  if (report.status === 'running') drive.append(element('p', 'Revisando metadados do Drive…'));
  if (report.status === 'error') drive.append(element('p', report.error, 'error'));
  if (report.status === 'complete') {
    drive.append(element('p', `Conta: ${report.user.emailAddress || report.user.displayName || 'Google'} · ${report.reviewed} arquivos revisados.`));
    if (report.partial) drive.append(element('p', 'Resultado parcial: há mais arquivos ou a pesquisa foi incompleta. Limite de 1.000 arquivos por revisão.', 'error'));
    drive.append(element('p', `${report.findings.length} arquivos merecem revisão. As indicações não comprovam malware ou acesso indevido.`));
    const list = element('ul', '');
    for (const file of report.findings) {
      const li = element('li', '');
      const link = element('a', file.name || 'Arquivo sem nome');
      link.href = 'https://drive.google.com/file/d/' + encodeURIComponent(file.id) + '/view';
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      li.append(link, element('div', file.reasons.join(' ')));
      list.append(li);
    }
    drive.append(list);
    if (!report.findings.length) drive.append(element('p', 'Nenhum indicador nas regras utilizadas. Isso não comprova que a conta ou os arquivos estejam seguros.'));
  }
  const pc = $('#pc-result');
  pc.replaceChildren();
  if (!data.windows) pc.append(element('p', 'Disponível no aplicativo executado em um PC Windows.'));
  if (data.pc.status === 'running') pc.append(element('p', 'Aguardando o Microsoft Defender. A varredura pode levar vários minutos; mantenha o aplicativo aberto.'));
  if (data.pc.status === 'error') pc.append(element('p', data.pc.error, 'error'));
  if (data.pc.status === 'complete') {
    const p = data.pc.result.protection;
    pc.append(element('p', data.pc.operation === 'scan' ? 'O comando de varredura retornou. Confira abaixo a data da última varredura rápida.' : 'Estado atual da proteção consultado.'));
    const list = element('ul', '');
    for (const text of [
      `Antivírus: ${p.AntivirusEnabled ? 'ativado' : 'desativado'}`,
      `Proteção em tempo real: ${p.RealTimeProtectionEnabled ? 'ativada' : 'desativada'}`,
      `Assinaturas atualizadas em: ${dateLabel(p.AntivirusSignatureLastUpdated)}`,
      `Última varredura rápida iniciada: ${dateLabel(p.QuickScanStartTime)}`,
      `Última varredura rápida encerrada: ${dateLabel(p.QuickScanEndTime)}`
    ]) list.append(element('li', text));
    pc.append(list, element('p', 'Histórico recente do Defender (até 20 detecções, inclusive anteriores a esta varredura):'));
    const history = data.pc.result.history || [];
    if (!history.length) pc.append(element('p', 'Nenhuma detecção retornada no histórico consultado. Isso não garante ausência de ameaças.'));
    for (const threat of history) {
      pc.append(element('p', `Ameaça ${threat.ThreatID} · ${dateLabel(threat.InitialDetectionTime)} · ação de proteção ${threat.ActionSuccess ? 'bem-sucedida' : 'não confirmada'}`));
      pc.append(element('pre', (threat.Resources || []).join('\n')));
    }
    pc.append(element('p', 'Para detalhes e ações de proteção, abra Segurança do Windows → Proteção contra vírus e ameaças → Histórico de proteção.'));
  }
}

async function refreshSecurity() {
  if (securityBusy) return;
  securityBusy = true;
  try { renderSecurity(await api('/api/security')); }
  catch (error) { $('#security-error').textContent = error.message; }
  finally { securityBusy = false; }
}

async function securityAction(path, data = {}) {
  $('#security-error').textContent = '';
  const result = await api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  await refreshSecurity();
  return result;
}

function onSecurityClick(selector, action) {
  $(selector).onclick = async () => {
    $(selector).disabled = true;
    try { await action(); }
    catch (error) { $('#security-error').textContent = error.message; }
    finally { $(selector).disabled = false; await refreshSecurity(); }
  };
}

onSecurityClick('#google-connect', async () => {
  const file = $('#google-config').files[0];
  if (!file || file.size > 32768) throw Error('Selecione o JSON OAuth do aplicativo (até 32 KB).');
  let config;
  try { config = JSON.parse(await file.text()); }
  catch { throw Error('O arquivo selecionado não é um JSON válido.'); }
  const result = await securityAction('/api/google/connect', config);
  $('#google-config').value = '';
  window.location.assign(result.url);
});
onSecurityClick('#google-disconnect', () => securityAction('/api/google/disconnect'));
onSecurityClick('#drive-scan', () => securityAction('/api/google/scan'));
onSecurityClick('#pc-status', () => securityAction('/api/pc/status'));
onSecurityClick('#pc-scan', async () => {
  if (confirm('Iniciar a varredura rápida? O Microsoft Defender pode colocar ameaças em quarentena ou aplicar as ações configuradas no Windows.')) {
    await securityAction('/api/pc/scan', { confirmed: true });
  }
});
refreshSecurity();
setInterval(refreshSecurity, 3000);
