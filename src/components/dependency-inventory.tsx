'use client';

import { useState } from 'react';
import type { Dependency } from '../domain/types.ts';

export function DependencyInventory({ dependencies }: { dependencies: Dependency[] }) {
  const [visible, setVisible] = useState(false);

  return (
    <div className="dependency-inventory">
      <div className="dependency-inventory-heading">
        <div>
          <h3>Full dependency inventory</h3>
          <p>Resolved lockfile versions where available; declared ranges remain visible.</p>
        </div>
        <button
          className="secondary-button dependency-inventory-toggle"
          type="button"
          aria-expanded={visible}
          onClick={() => setVisible((current) => !current)}
        >
          {visible ? 'Hide inventory' : `Show ${dependencies.length} dependencies`}
        </button>
      </div>

      {visible && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Package</th>
                <th>Requested version</th>
                <th>Resolved version</th>
                <th>Relationship</th>
                <th>Scope</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {dependencies.map((dependency) => (
                <tr
                  key={`${dependency.manifest}:${dependency.scope}:${dependency.name}:${dependency.resolvedVersion ?? dependency.requestedVersion}`}
                >
                  <td className="strong mono">{dependency.name}</td>
                  <td className="mono">{dependency.requestedVersion}</td>
                  <td className="mono">{dependency.resolvedVersion ?? 'Not resolved'}</td>
                  <td>{dependency.relationship ?? 'unknown'}</td>
                  <td>{dependency.scope}</td>
                  <td className="mono small">{dependency.lockfile ?? dependency.manifest}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
