let darkMode = false;
const originalNodeStyles = {};

function applyNodeStyles() {
  const allNodes = network.body.data.nodes.get();
  allNodes.forEach(n => {
    if (!originalNodeStyles[n.id]) {
      originalNodeStyles[n.id] = {
        background: n.color?.background || "#64b5f6",
        border: n.color?.border || "#1565c0",
        font: n.font?.color || "#343434"
      };
    }

    let bgColor = originalNodeStyles[n.id].background;
    let borderColor = originalNodeStyles[n.id].border;
    let fontColor = darkMode ? "#e0e0e0" : "#000000";

    if (darkMode) {
      if (n.id.endsWith(".exe")) {
        bgColor = "#00bcd4";
        borderColor = "#00acc1";
      } else if (!n.id.includes("::")) {
        const isSystem = n.id.toLowerCase().startsWith("api") ||
                        n.id.toLowerCase().startsWith("kernel") ||
                        n.id.toLowerCase().startsWith("user") ||
                        n.id.toLowerCase().startsWith("gdi") ||
                        n.id.toLowerCase().includes("windows");

        if (isSystem) {
          bgColor = "#1976d2";
          borderColor = "#64b5f6";
        } else {
          bgColor = "#f57c00";
          borderColor = "#ffb74d";
        }
      } else {
        bgColor = "#4caf50";
        borderColor = "#66bb6a";
      }
    }

    network.body.data.nodes.update({
      id: n.id,
      color: {
        background: bgColor,
        border: borderColor
      },
      font: {
        color: fontColor,
        size: (n.id.endsWith(".exe") || (!n.id.includes("::") && !n.id.endsWith(".exe"))) ? 20 : 13,
        face: "arial",
        bold: true
      }
    });
  });
}

function toggleDLLVisibility() {
  const selected = document.getElementById('dllSelector').value;
  const allNodes = network.body.data.nodes.get();
  const allEdges = network.body.data.edges.get();
  const visibleNodes = new Set();
  const visibleEdges = [];

  if (selected === "ALL") {
    allNodes.forEach(n => {
      network.body.data.nodes.update({ id: n.id, hidden: false });
    });
    allEdges.forEach(e => {
      network.body.data.edges.update({ id: e.id, hidden: false });
    });
    return;
  }

  allNodes.forEach(n => {
    if (n.id === selected || n.id.startsWith(selected + "::")) {
      visibleNodes.add(n.id);
    }
  });

  allEdges.forEach(e => {
    if (visibleNodes.has(e.from) && visibleNodes.has(e.to)) {
      visibleEdges.push(e.id);
    }
  });

  allNodes.forEach(n => {
    network.body.data.nodes.update({ id: n.id, hidden: !visibleNodes.has(n.id) });
  });
  allEdges.forEach(e => {
    network.body.data.edges.update({ id: e.id, hidden: !visibleEdges.includes(e.id) });
  });
}

function searchFunctionName() {
  const term = document.getElementById('funcSearchBox').value.toLowerCase();
  const allNodes = network.body.data.nodes.get();
  const allEdges = network.body.data.edges.get();

  const visibleNodes = new Set();
  const visibleEdges = [];

  if (!term) {
    allNodes.forEach(n => {
      network.body.data.nodes.update({ id: n.id, hidden: false });
    });
    allEdges.forEach(e => {
      network.body.data.edges.update({ id: e.id, hidden: false });
    });
    return;
  }

  // Match function names
  const matchedFunctions = allNodes.filter(n =>
    n.id.includes("::") && n.label.toLowerCase().includes(term)
  );

  matchedFunctions.forEach(funcNode => {
    const parentDLL = funcNode.id.split("::")[0];
    visibleNodes.add(funcNode.id);
    visibleNodes.add(parentDLL);
  });

  // Keep only relevant edges
  allEdges.forEach(e => {
    if (visibleNodes.has(e.from) && visibleNodes.has(e.to)) {
      visibleEdges.push(e.id);
    }
  });

  // Apply visibility
  allNodes.forEach(n => {
    network.body.data.nodes.update({ id: n.id, hidden: !visibleNodes.has(n.id) });
  });
  allEdges.forEach(e => {
    network.body.data.edges.update({ id: e.id, hidden: !visibleEdges.includes(e.id) });
  });
}

function toggleSystemDLLs() {
  const showOnlySystem = document.getElementById('systemToggle').checked;
  const allNodes = network.body.data.nodes.get();
  const allEdges = network.body.data.edges.get();

  const visibleNodes = new Set();
  const visibleEdges = [];

  // Define system DLL logic
  const isSystemDLL = (label) => {
    const l = label.toLowerCase();
    return (
      l.endsWith(".dll") &&
      (l.startsWith("api") || l.startsWith("ms") || l.startsWith("kernel") ||
      l.startsWith("advapi") || l.startsWith("ws2_32") || l.startsWith("win") ||
      l.startsWith("ntdll") || l.startsWith("user32") || l.startsWith("gdi32"))
    );
  };

  if (!showOnlySystem) {
    // Show all
    allNodes.forEach(n => network.body.data.nodes.update({ id: n.id, hidden: false }));
    allEdges.forEach(e => network.body.data.edges.update({ id: e.id, hidden: false }));
    return;
  }

  // Mark only system DLLs and their subnodes
  const systemDLLs = allNodes.filter(n => !n.id.includes("::") && isSystemDLL(n.label));
  systemDLLs.forEach(dll => visibleNodes.add(dll.id));

  allNodes.forEach(n => {
    if (n.id.includes("::")) {
      const parentDLL = n.id.split("::")[0];
      if (visibleNodes.has(parentDLL)) visibleNodes.add(n.id);
    }
  });

  allEdges.forEach(e => {
    if (visibleNodes.has(e.from) && visibleNodes.has(e.to)) {
      visibleEdges.push(e.id);
    }
  });

  // Apply visibility
  allNodes.forEach(n => {
    network.body.data.nodes.update({ id: n.id, hidden: !visibleNodes.has(n.id) });
  });
  allEdges.forEach(e => {
    network.body.data.edges.update({ id: e.id, hidden: !visibleEdges.includes(e.id) });
  });
}

function toggleDarkMode() {
  darkMode = !darkMode;
  const dependencyGraphSection = document.getElementById('dependency-graph-section');
  //const darkModeToggleBtn = document.getElementById('darkModeToggle');
  //const icon = darkModeToggleBtn.querySelector('i');
  if(dependencyGraphSection){
    if (darkMode) {
      dependencyGraphSection.classList.add('dark-mode');
      //icon.className = 'fa-regular fa-sun'; // Replace the class with the new one
    } else {
      dependencyGraphSection.classList.remove('dark-mode');
      //icon.className = 'fa-regular fa-moon'; // Replace the class with the new one
    }
    applyNodeStyles(); // reuse
  }
}

// Debounce function and event listener for search
let debounceTimer;
function debouncedSearch() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(searchFunctionName, 500); // Adjust delay if needed
}

document.addEventListener('DOMContentLoaded', function() {
  const funcSearchBox = document.getElementById('funcSearchBox');
  if (funcSearchBox) {
    funcSearchBox.addEventListener('input', debouncedSearch);
  }

  // Sidebar navigation logic for report.html and dependency graph
  const reportSidebar = document.getElementById('report-sidebar');
  const dependencyGraphSection = document.getElementById('dependency-graph-section');
  const reportContentWrapper = document.getElementById('report-content-wrapper');

  if (reportSidebar) {
    // Initially hide the dependency graph section
    if (dependencyGraphSection) {
      dependencyGraphSection.style.display = 'none';
    }

    reportSidebar.addEventListener('click', function(event) {
      event.preventDefault();
      const target = event.target;

      if (target.matches('.list-group-item')) {
        // Remove active class from current active item
        const currentActive = reportSidebar.querySelector('.list-group-item.active');
        if (currentActive) {
          currentActive.classList.remove('active');
        }

        // Add active class to clicked item
        target.classList.add('active');

        // Hide all content sections and the dependency graph section
        document.querySelectorAll('.report-content-section').forEach(section => {
          section.style.display = 'none';
        });
        if (dependencyGraphSection) {
          dependencyGraphSection.style.display = 'none';
        }
        if (reportContentWrapper) {
          reportContentWrapper.style.display = 'none';
        }

        // Show the selected content section or dependency graph
        const sectionId = target.dataset.section;
        if (sectionId === 'dependency-graph') {
          if (dependencyGraphSection) {
            dependencyGraphSection.style.display = 'block';
            if (window.network) {
              window.network.fit(); // Center the graph
            }
          }
        } else {
          const activeSection = document.getElementById(sectionId + '-section');
          if (activeSection) {
            activeSection.style.display = 'block';
          }
          if (reportContentWrapper) {
            reportContentWrapper.style.display = 'block';
          }
        }
      }
    });

    // Set Basic File Info as active and visible by default
    const basicFileInfoLink = reportSidebar.querySelector('[data-section="basic-file-info"]');
    if (basicFileInfoLink) {
      basicFileInfoLink.classList.add('active');
      const basicFileInfoSection = document.getElementById('basic-file-info-section');
      if (basicFileInfoSection) {
        basicFileInfoSection.style.display = 'block';
      }
      if (reportContentWrapper) {
        reportContentWrapper.style.display = 'block';
      }
    }
  }

  const downloadGraphBtn = document.getElementById('downloadGraphBtn');

  if (downloadGraphBtn) {
    downloadGraphBtn.addEventListener('click', function () {
      if (
        window.network &&
        window.network.canvas &&
        window.network.canvas.frame &&
        window.network.canvas.frame.canvas
      ) {
        const canvas = window.network.canvas.frame.canvas;
        const imageData = canvas.toDataURL('image/png');

        const a = document.createElement('a');
        a.href = imageData;
        a.download = 'network_graph.png';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      } else {
        console.error("❌ Canvas is not accessible. Check if the network is initialized.");
        console.log("window.network:", window.network);
      }
    });
  }

  const input = document.getElementById('dlls');
  const countText = document.getElementById('dlls-count');
  const list = document.getElementById('dlls-list');
  if(input){
  input.addEventListener('change', function () {
    const files = Array.from(this.files);

    countText.textContent = `${files.length} file${files.length > 1 ? 's' : ''} selected:`;

    // Clear previous list
    list.innerHTML = '';

    files.forEach(file => {
      const li = document.createElement('li');
      li.textContent = file.name;
      list.appendChild(li);
    });
  });
}
});