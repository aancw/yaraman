document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);

            fetch('/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.report_id) {
                    window.location.href = '/results?report_id=' + data.report_id;
                } else {
                    console.error('Scan failed:', data.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    }

    // Toggle the sidebar
    const menuToggle = document.getElementById('menu-toggle');
    if (menuToggle) {
        menuToggle.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('wrapper').classList.toggle('toggled');
        });
    }

    // Handle hex dump button click
    document.querySelectorAll('.view-hex-dump-btn').forEach(button => {
        button.addEventListener('click', function() {
            const fileName = this.dataset.fileName;
            const hexDumpOutput = this.nextElementSibling; // The <pre> tag

            fetch(`/hex_dump/${fileName}`)
                .then(response => response.json())
                .then(data => {
                    if (data.hex_dump) {
                        hexDumpOutput.textContent = data.hex_dump;
                    } else {
                        hexDumpOutput.textContent = 'Error: Could not retrieve hex dump.';
                    }
                })
                .catch(error => {
                    console.error('Error fetching hex dump:', error);
                    hexDumpOutput.textContent = 'Error: Could not retrieve hex dump.';
                });
        });
    });
});