<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced CVE Intelligence</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .priority-P0 { background-color: #dc3545 !important; color: white; font-weight: bold; }
        .priority-P1 { background-color: #fd7e14 !important; color: white; }
        .badge-mitre { background-color: #6610f2; color: white; font-size: 0.8rem; }
        .badge-poc { border: 1px solid #198754; color: #198754; font-size: 0.8rem; text-decoration: none; }
        .badge-poc:hover { background-color: #198754; color: white; }
    </style>
</head>
<body>

<div class="container-fluid py-5 px-5">
    <div class="card shadow-sm border-0 rounded-4 p-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2 class="fw-bold text-dark">🛡️ Advanced CVE & Exploit Intelligence</h2>
            <div class="d-flex gap-3">
                <input type="text" id="searchInput" class="form-control" placeholder="CVE veya Teknik Ara...">
            </div>
        </div>

        <div class="table-responsive">
            <table class="table table-hover align-middle">
                <thead class="table-dark">
                    <tr>
                        <th>CVE ID</th>
                        <th>Öncelik</th>
                        <th>Puan</th>
                        <th>MITRE ATT&CK</th>
                        <th>Exploit / PoC</th>
                        <th>Açıklama</th>
                        <th>İşlem</th>
                    </tr>
                </thead>
                <tbody id="tableBody">
                    <tr><td colspan="7" class="text-center">Yükleniyor...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
    async function loadData() {
        try {
            const res = await fetch('data.json?v=' + Date.now());
            const data = await res.json();
            const tableBody = document.getElementById('tableBody');
            tableBody.innerHTML = '';

            data.forEach(item => {
                const pClass = item.priority ? item.priority.split(' ')[0] : 'P3';
                const row = `
                    <tr>
                        <td class="fw-bold text-primary">${item.id}</td>
                        <td><span class="badge priority-${pClass}">${item.priority}</span></td>
                        <td><span class="badge bg-dark">${item.severity}</span></td>
                        <td><span class="badge badge-mitre">${item.mitre || 'N/A'}</span></td>
                        <td>
                            <a href="${item.poc_link}" target="_blank" class="badge badge-poc">
                                🔍 PoC Ara
                            </a>
                        </td>
                        <td class="small text-muted" style="max-width:350px;">${item.description}</td>
                        <td>
                            <a href="${item.link}" target="_blank" class="btn btn-sm btn-outline-primary">Detay</a>
                        </td>
                    </tr>`;
                tableBody.innerHTML += row;
            });
        } catch (e) {
            tableBody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Veri yüklenemedi.</td></tr>';
        }
    }
    loadData();
</script>
</body>
</html>
